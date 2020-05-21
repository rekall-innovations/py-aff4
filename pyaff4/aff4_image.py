# Copyright 2014 Google Inc. All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may not
# use this file except in compliance with the License.  You may obtain a copy of
# the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.  See the
# License for the specific language governing permissions and limitations under
# the License.

"""This module implements the standard AFF4 Image."""
from __future__ import division
from __future__ import unicode_literals
from builtins import range
from builtins import str
from past.utils import old_div
from builtins import object
import binascii
import logging
import lz4.block
import struct

from expiringdict import ExpiringDict

from CryptoPlus.Cipher import python_AES
import snappy
import zlib

from pyaff4 import aff4
from pyaff4 import lexicon
from pyaff4 import rdfvalue
from pyaff4 import registry
from pyaff4 import hashes, zip


LOGGER = logging.getLogger("pyaff4")
DEBUG = False

class _CompressorStream(object):
    """A stream which chunks up another stream.

    Each read() operation will return a compressed chunk.
    """
    def __init__(self, owner, stream):
        self.owner = owner
        self.stream = stream
        self.chunk_count_in_bevy = 0
        self.size = 0
        self.bevy_index = []
        self.bevy_length = 0

    def tell(self):
        return self.stream.tell()

    def read(self, _):
        # Stop copying when the bevy is full.
        if self.chunk_count_in_bevy >= self.owner.chunks_per_segment:
            return ""

        chunk = self.stream.read(self.owner.chunk_size)
        if not chunk:
            return ""

        self.size += len(chunk)

        if self.owner.compression == lexicon.AFF4_IMAGE_COMPRESSION_ZLIB:
            compressed_chunk = zlib.compress(chunk)
        elif self.owner.compression == lexicon.AFF4_IMAGE_COMPRESSION_LZ4:
            compressed_chunk = lz4.block.compress(chunk)
        elif (snappy and self.owner.compression ==
              lexicon.AFF4_IMAGE_COMPRESSION_SNAPPY):
            compressed_chunk = snappy.compress(chunk)
        elif self.owner.compression in (lexicon.AFF4_IMAGE_COMPRESSION_STORED, 
                                        lexicon.AFF4_IMAGE_COMPRESSION_NONE):
            compressed_chunk = chunk

        compressedLen = len(compressed_chunk)
        self.chunk_count_in_bevy += 1

        if compressedLen < self.owner.chunk_size - 16:
            self.bevy_index.append((self.bevy_length, compressedLen))
            self.bevy_length += compressedLen
            return compressed_chunk
        else:
            self.bevy_index.append((self.bevy_length, self.owner.chunk_size))
            self.bevy_length += self.owner.chunk_size
            return chunk


class AFF4Image(aff4.AFF4Stream):

    def setCompressionMethod(self, method):
        if method in [zip.ZIP_STORED, lexicon.AFF4_IMAGE_COMPRESSION_STORED, lexicon.AFF4_IMAGE_COMPRESSION_NONE]:
            self.compression = lexicon.AFF4_IMAGE_COMPRESSION_STORED
        elif method in [lexicon.AFF4_IMAGE_COMPRESSION_SNAPPY, lexicon.AFF4_IMAGE_COMPRESSION_SNAPPY_SCUDETTE,
                         lexicon.AFF4_IMAGE_COMPRESSION_ZLIB, lexicon.AFF4_IMAGE_COMPRESSION_LZ4 ]:
            self.compression = method
        else:
            raise RuntimeError("Bad compression parameter")

    @staticmethod
    def NewAFF4Image(resolver, image_urn, volume_urn, type=lexicon.AFF4_IMAGE_TYPE):
        with resolver.AFF4FactoryOpen(volume_urn) as volume:
            # Inform the volume that we have a new image stream contained within
            # it.
            volume.children.add(image_urn)

            resolver.Add(volume_urn, image_urn, lexicon.AFF4_TYPE, rdfvalue.URN(
                type))

            resolver.Set(lexicon.transient_graph, image_urn, lexicon.AFF4_STORED,
                         rdfvalue.URN(volume_urn))

            res = resolver.AFF4FactoryOpen(image_urn)
            res.properties.writable = True
            return res

    def LoadFromURN(self):
        volume_urn = self.resolver.GetUnique(lexicon.transient_graph, self.urn, lexicon.AFF4_STORED)
        #if not volume_urn:
        #    raise IOError("Unable to find storage for urn %s" % self.urn)

        appendMode = self.resolver.GetUnique(lexicon.transient_graph,
                                                         self.urn , lexicon.AFF4_STREAM_WRITE_MODE)
        if appendMode != None and str(appendMode) in ["truncate", "append", "random" ]:
            self.properties.writable = True

        self.lexicon = self.resolver.lexicon

        self.chunk_size = int(self.resolver.GetUnique(volume_urn,
            self.urn, self.lexicon.chunkSize) or 32 * 1024)

        self.chunks_per_segment = int(self.resolver.GetUnique(volume_urn,
            self.urn, self.lexicon.chunksPerSegment) or 1024)

        sz = self.resolver.GetUnique(volume_urn, self.urn, self.lexicon.streamSize) or 0
        self.size = int(sz)

        self.compression = (self.resolver.GetUnique(volume_urn,
            self.urn, self.lexicon.compressionMethod) or
            lexicon.AFF4_IMAGE_COMPRESSION_ZLIB)

        # A buffer for overlapped writes which do not fit into a chunk.
        self.buffer = b""

        # Compressed chunks in the bevy.
        self.bevy = []

        # Length of all chunks in the bevy.
        self.bevy_length = 0

        # List of (bevy offsets, compressed chunk length).
        self.bevy_index = []
        self.chunk_count_in_bevy = 0
        self.bevy_number = 0

        self.cache = ExpiringDict(max_len=1000, max_age_seconds=10)

        # used for identifying in-place writes to bevys
        self.bevy_is_loaded_from_disk = False

        # used for identifying if a bevy now exceeds its initial size
        self.bevy_size_has_changed = False


    def _write_bevy_index(self, volume, bevy_urn, bevy_index, flush=False):
        """Write the index segment for the specified bevy_urn."""
        bevy_index_urn = bevy_urn.Append("index")
        with volume.CreateMember(bevy_index_urn) as bevy_index_segment:
            # Old style index is just a list of lengths.
            bevy_index = [x[1] for x in bevy_index]
            bevy_index_segment.Write(
                struct.pack("<" + "I"*len(bevy_index), bevy_index))

        if flush:
            self.resolver.Close(bevy_index_segment)

    def Length(self):
        return self.size

    def WriteStream(self, source_stream, progress=None):
        """Copy data from a source stream into this stream."""
        if progress is None:
            if DEBUG:
                progress = aff4.DEFAULT_PROGRESS
            else:
                progress = aff4.EMPTY_PROGRESS

        volume_urn = self.resolver.GetUnique(None, self.urn, lexicon.AFF4_STORED)
        if not volume_urn:
            raise IOError("Unable to find storage for urn %s" %
                          self.urn)

        with self.resolver.AFF4FactoryOpen(volume_urn) as volume:
            # Write a bevy at a time.
            while 1:
                stream = _CompressorStream(self, source_stream)

                bevy_urn = self.urn.Append("%08d" % self.bevy_number)
                progress.start = (self.bevy_number *
                                  self.chunks_per_segment *
                                  self.chunk_size)

                with volume.CreateMember(bevy_urn) as bevy:
                    bevy.WriteStream(stream, progress=progress)

                self._write_bevy_index(volume, bevy_urn, stream.bevy_index)

                # Make another bevy.
                self.bevy_number += 1
                self.size += stream.size
                self.writeptr += stream.size

                # Last iteration - the compressor stream quit before the bevy is
                # full.
                if stream.chunk_count_in_bevy != self.chunks_per_segment:
                    break

        self._write_metadata()

    def Write(self, data):
        #hexdump(data)
        self.MarkDirty()
        self.buffer += data
        idx = 0

        while len(self.buffer) - idx > self.chunk_size:
            chunk = self.buffer[idx:idx+self.chunk_size]
            idx += self.chunk_size
            self.FlushChunk(chunk)

        if idx > 0:
            self.buffer = self.buffer[idx:]

        self.writeptr += len(data)
        if self.writeptr > self.size:
            self.size = self.writeptr

        return len(data)

    def FlushChunk(self, chunk):
        if len(chunk) == 0:
            return

        bevy_offset = self.bevy_length

        if self.compression == lexicon.AFF4_IMAGE_COMPRESSION_ZLIB:
            compressed_chunk = zlib.compress(chunk)
        elif self.compression == lexicon.AFF4_IMAGE_COMPRESSION_LZ4:
            compressed_chunk = lz4.block.compress(chunk)
        elif (snappy and self.compression ==
              lexicon.AFF4_IMAGE_COMPRESSION_SNAPPY):
            compressed_chunk = snappy.compress(chunk)
        elif self.compression in (lexicon.AFF4_IMAGE_COMPRESSION_STORED, 
                                lexicon.AFF4_IMAGE_COMPRESSION_NONE):
            compressed_chunk = chunk

        compressedLen = len(compressed_chunk)

        if compressedLen < self.chunk_size - 16:
            self.bevy_index.append((bevy_offset, compressedLen))
            self.bevy.append(compressed_chunk)
            self.bevy_length += compressedLen
        else:
            self.bevy_index.append((bevy_offset, self.chunk_size))
            self.bevy.append(chunk)
            self.bevy_length += self.chunk_size

        #self.bevy_index.append((bevy_offset, len(compressed_chunk)))
        #self.bevy.append(compressed_chunk)
        #self.bevy_length += len(compressed_chunk)
        self.chunk_count_in_bevy += 1

        #self.buffer = chunk[self.chunk_size:]
        if self.chunk_count_in_bevy >= self.chunks_per_segment:
            self._FlushBevy()


    def _FlushBevy(self):
        volume_urn = self.resolver.GetUnique(lexicon.transient_graph, self.urn, lexicon.AFF4_STORED)
        if not volume_urn:
            raise IOError("Unable to find storage for urn %s" % self.urn)

        # Bevy is empty nothing to do.
        if not self.bevy:
            return

        bevy_urn = self.urn.Append("%08d" % self.bevy_number)
        with self.resolver.AFF4FactoryOpen(volume_urn) as volume:
            self._write_bevy_index(volume, bevy_urn, self.bevy_index, flush=True)

            with volume.CreateMember(bevy_urn) as bevy:
                bevy.Write(b"".join(self.bevy))

                # We dont need to hold these in memory any more.
                bevy.FlushAndClose()

        # In Python it is more efficient to keep a list of chunks and then join
        # them at the end in one operation.
        self.chunk_count_in_bevy = 0
        self.bevy_number += 1
        self.bevy = []
        self.bevy_index = []
        self.bevy_length = 0

    def _write_metadata(self):
        volume_urn = self.resolver.GetUnique(lexicon.transient_graph, self.urn, lexicon.AFF4_STORED)
        self.resolver.Add(volume_urn, self.urn, lexicon.AFF4_TYPE,
                          rdfvalue.URN(lexicon.AFF4_IMAGE_TYPE))

        self.resolver.Set(volume_urn, self.urn, lexicon.AFF4_IMAGE_CHUNK_SIZE,
                          rdfvalue.XSDInteger(self.chunk_size))

        self.resolver.Set(volume_urn, self.urn, lexicon.AFF4_IMAGE_CHUNKS_PER_SEGMENT,
                          rdfvalue.XSDInteger(self.chunks_per_segment))

        self.resolver.Set(volume_urn, self.urn, lexicon.AFF4_STREAM_SIZE,
                          rdfvalue.XSDInteger(self.Size()))

        self.resolver.Set(volume_urn,
            self.urn, lexicon.AFF4_IMAGE_COMPRESSION,
            rdfvalue.URN(self.compression))

    def FlushBuffers(self):
        if self.IsDirty():
            # Flush the last chunk.
            chunk = self.buffer
            chunkSize = len(chunk)
            if chunkSize <= self.chunk_size:
                topad = 0
                # if the data is sub chunk sized, pad with zeros
                # (this generally only happens for the last chunk in the image stream)
                if len(chunk) != self.chunk_size:
                    topad = self.chunk_size - (self.size % self.chunk_size)
                    chunk += b"\x00" * topad

                self.FlushChunk(chunk)
                self.buffer = b""
                self.writeptr += topad

            else:
                raise Exception("Illegal state")

    def Flush(self):
        if self.IsDirty():
            # Flush the last chunk.
            # If it is sub chunk-size it out to chunk_size
            chunk = self.buffer
            chunkSize = len(chunk)
            if chunkSize <= self.chunk_size:
                # if the data is sub chunk sized, pad with zeros
                # (this generally only happens for the last chunk in the image stream)
                topad = self.chunk_size - (self.size % self.chunk_size)
                if topad < self.chunk_size:
                    chunk += b"\x00" * topad

            self.FlushChunk(chunk)

            self._FlushBevy()

            self._write_metadata()

        return super(AFF4Image, self).Flush()

    def Abort(self):
        if self.IsDirty():
            # for standard image streams, the current bevy hasnt been flushed.
            volume_urn = self.resolver.GetUnique(lexicon.transient_graph, self.urn, lexicon.AFF4_STORED)

            with self.resolver.AFF4FactoryOpen(volume_urn, version=self.version) as volume:
                # make sure that the zip file is marked as dirty
                volume._dirty = True

                # create a set of the bevy related objects
                bevvys_to_remove = []
                for i in range(0, self.bevy_number+1):
                    seg_arn = self.urn.Append("%08d" % i)
                    idx_arn = self.urn.Append("%08d.index" % i)
                    bevvys_to_remove.append(seg_arn)
                    bevvys_to_remove.append(idx_arn)

                volume.RemoveMembers(bevvys_to_remove)
                volume.children.remove(self.urn)

            self.resolver.DeleteSubject(self.urn)
            self._dirty = False

    def Close(self):
        pass

    def Read(self, length):
        length = int(length)
        if length == 0:
            return ""

        length = min(length, self.Size() - self.readptr)

        initial_chunk_id, initial_chunk_offset = divmod(self.readptr,
                                                        self.chunk_size)

        final_chunk_id, _ = divmod(self.readptr + length - 1, self.chunk_size)

        # We read this many full chunks at once.
        chunks_to_read = final_chunk_id - initial_chunk_id + 1
        chunk_id = initial_chunk_id
        result = b""

        while chunks_to_read > 0:
            #chunks_read, data = self._ReadPartial(chunk_id, chunks_to_read)
            if self.properties.writable:
                chunks_read, data = self._ReadPartial(chunk_id, chunks_to_read)
            else:
                chunks_read, data = self._ReadPartialRO(chunk_id, chunks_to_read)
            if chunks_read == 0:
                break

            chunks_to_read -= chunks_read
            result += data

        if initial_chunk_offset:
            result = result[initial_chunk_offset:]

        result = result[:length]

        self.readptr += len(result)

        return result

    def ReadAll(self):
        res = b""
        while True:
            toRead = 32 * 1024
            data = self.Read(toRead)
            if data == None or len(data) == 0:
                # EOF
                return res
            else:
                res += data

    def _parse_bevy_index(self, bevy):
        """Read and return the bevy's index.

        This version deals with pre standard versions in which the
        index stream consists of a list of chunk offsets:

        - Evimetry uses a 1 based list (so the first entry in the index
          is the offset of the first chunk (and the 0'th chunk is
          assumed to start at 0).
        - Scudette's version always uses 0 for the offset of the first
          chunk and the last chunk's length is assumed from the total
          bevy size.
        """
        bevy_index_urn = bevy.urn.Append("index")
        if LOGGER.isEnabledFor(logging.INFO):
            LOGGER.info("Loading Bevy Index %s", bevy_index_urn)
        with self.resolver.AFF4FactoryOpen(bevy_index_urn) as bevy_index:
            bevy_index_data = bevy_index.Read(bevy_index.Size())
            format_string = "<" + "I" * (bevy_index.Size() // struct.calcsize("I"))
            chunk_offsets = struct.unpack(format_string, bevy_index_data)

            # Convert the index into standard form:
            # list of (offset, compressed length)

            # Evimetry's implementation
            if chunk_offsets[0] != 0:
                result = [(0, chunk_offsets[0])]
            else:
                # Scudette's implementation.
                result = []

            for i in range(len(chunk_offsets)-1):
                result.append(
                    (chunk_offsets[i],
                     chunk_offsets[i+1] - chunk_offsets[i]))

            # Last chunk's size is inferred from the rest of the bevy.
            if chunk_offsets[-1] < bevy.Size():
                result.append((chunk_offsets[-1],
                               bevy.Size() - chunk_offsets[-1]))
            if LOGGER.isEnabledFor(logging.INFO):
                LOGGER.info("Loaded Bevy Index %s entries=%x", bevy_index_urn, len(result))
            return result

    def reloadBevy(self, bevy_id):
        bevy_urn = self.urn.Append("%08d" % bevy_id)
        bevy_index_urn = rdfvalue.URN("%s.index" % bevy_urn)
        if LOGGER.isEnabledFor(logging.INFO):
            LOGGER.info("Reload Bevy %s", bevy_urn)
        chunks = []

        with self.resolver.AFF4FactoryOpen(bevy_urn, version=self.version) as bevy:
            bevy_index = self._parse_bevy_index(bevy)
            for i in range(0, len(bevy_index)):
                off, sz = bevy_index[i]
                bevy.SeekRead(off, 0)
                chunk = bevy.Read(sz)
                chunks.append(self.onChunkLoad(chunk, bevy_id, i))

                # trim the chunk if it is the final one and it exceeds the size of the stream
                endOfChunkAddress = (bevy_id * self.chunks_per_segment + i + 1) * self.chunk_size
                if endOfChunkAddress > self.size:
                    toKeep = self.chunk_size - (endOfChunkAddress - self.size)
                    chunk = chunks[i][0:toKeep]
                    chunks[i] = chunk
                    self.cache[i] = chunk
                    bevy_index = bevy_index[0:i+1]
                    break
        self.bevy = chunks
        self.bevy_index = bevy_index
        self.bevy_length = len(bevy_index)
        self.bevy_number = bevy_id
        self.bevy_is_loaded_from_disk = True

    def onChunkLoad(self, chunk, bevy_id, chunk_id):
        return self.doDecompress(chunk, bevy_id*self.chunks_per_segment + chunk_id)

    def _ReadPartialRO(self, chunk_id, chunks_to_read):
        chunks_read = 0
        result = b""
        if LOGGER.isEnabledFor(logging.INFO):
            LOGGER.info("ReadPartialRO chunk=%x count=%x", chunk_id, chunks_to_read)
        while chunks_to_read > 0:
            local_chunk_index = chunk_id % self.chunks_per_segment
            bevy_id = chunk_id // self.chunks_per_segment

            r = self.cache.get(chunk_id)
            if r != None:
                result += r
                chunks_to_read -= 1
                chunk_id += 1
                chunks_read += 1
                continue

            if not self.bevy_is_loaded_from_disk:
                self.reloadBevy(0)
                self.buffer = self.bevy[0]

            if bevy_id != self.bevy_number:
                self.reloadBevy(bevy_id)

            # read directly from the bevvy
            ss = len(self.bevy)
            if local_chunk_index < len(self.bevy):
                r = self.bevy[local_chunk_index]
                self.cache[chunk_id] = r
                result += r
                chunks_to_read -= 1
                chunk_id += 1
                chunks_read += 1
                continue

        return chunks_read, result

    def _ReadPartial(self, chunk_id, chunks_to_read):
        chunks_read = 0
        result = b""
        if LOGGER.isEnabledFor(logging.INFO):
            LOGGER.info("ReadPartial chunk=%x count=%x", chunk_id, chunks_to_read)
        while chunks_to_read > 0:
            local_chunk_index = chunk_id % self.chunks_per_segment
            bevy_id = chunk_id // self.chunks_per_segment

            r = self.cache.get(chunk_id)
            if r != None:
                result += r
                chunks_to_read -= 1
                chunk_id += 1
                chunks_read += 1
                continue

            if self._dirty and bevy_id == self.bevy_number:
                # try reading from the write buffer
                if local_chunk_index == self.chunk_count_in_bevy:
                    #if len(self.buffer) == self.chunk_size:
                    r = self.buffer
                    self.cache[chunk_id] = r
                    result += r
                    chunks_to_read -= 1
                    chunk_id += 1
                    chunks_read += 1
                    continue

                # try reading directly from the yet-to-be persisted bevvy
                ss = len(self.bevy)
                if local_chunk_index < len(self.bevy):
                    r = self.bevy[local_chunk_index]
                    self.cache[chunk_id] = r
                    #result += self.doDecompress(r, chunk_id)
                    result += r
                    chunks_to_read -= 1
                    chunk_id += 1
                    chunks_read += 1
                    continue

            bevy_id = old_div(chunk_id, self.chunks_per_segment)
            bevy_urn = self.urn.Append("%08d" % bevy_id)

            with self.resolver.AFF4FactoryOpen(bevy_urn, version=self.version) as bevy:
                while chunks_to_read > 0:
                    r = self.cache.get(chunk_id)
                    if r != None:
                        result += r
                        chunks_to_read -= 1
                        chunk_id += 1
                        chunks_read += 1
                        continue

                    # Read a full chunk from the bevy.
                    data = self._ReadChunkFromBevy(chunk_id, bevy)
                    self.cache[chunk_id] = data

                    result += data

                    chunks_to_read -= 1
                    chunk_id += 1
                    chunks_read += 1

                    # This bevy is exhausted, get the next one.
                    if bevy_id < old_div(chunk_id, self.chunks_per_segment):
                        break

        return chunks_read, result

    def _ReadChunkFromBevy(self, chunk_id, bevy):
        bevy_index = self._parse_bevy_index(bevy)
        chunk_id_in_bevy = chunk_id % self.chunks_per_segment

        if not bevy_index:
            LOGGER.error("Index empty in %s: %s", self.urn, chunk_id)
            raise IOError("Index empty in %s: %s" % (self.urn, chunk_id))

        # The segment is not completely full.
        if chunk_id_in_bevy >= len(bevy_index):
            LOGGER.error("Bevy index too short in %s: %s",
                         self.urn, chunk_id)
            raise IOError("Bevy index too short in %s: %s" % (
                self.urn, chunk_id))

        # The index is a list of (offset, compressed_length)
        chunk_offset, chunk_size = bevy_index[chunk_id_in_bevy]
        bevy.SeekRead(chunk_offset, 0)
        cbuffer = bevy.Read(chunk_size)

        return self.doDecompress(cbuffer, chunk_id)

    def doDecompress(self, cbuffer, chunk_id):

        if self.compression == lexicon.AFF4_IMAGE_COMPRESSION_ZLIB :
            if len(cbuffer) == self.chunk_size:
                return cbuffer
            return zlib.decompress(cbuffer)

        elif self.compression == lexicon.AFF4_IMAGE_COMPRESSION_LZ4 :
            if len(cbuffer) == self.chunk_size:
                return cbuffer
            return lz4.block.decompress(cbuffer, self.chunk_size)

        elif self.compression == lexicon.AFF4_IMAGE_COMPRESSION_SNAPPY_SCUDETTE:
            # Backwards compatibility with Scudette's AFF4 implementation.
            # Chunks are always compressed.
            return snappy.decompress(cbuffer)

        elif self.compression == lexicon.AFF4_IMAGE_COMPRESSION_SNAPPY:

            if len(cbuffer) == self.chunk_size:
                # Buffer is not compressed.
                return cbuffer
            try:
                return snappy.decompress(cbuffer)
            except Exception as e:
                raise e

        elif self.compression in (lexicon.AFF4_IMAGE_COMPRESSION_STORED, 
                                lexicon.AFF4_IMAGE_COMPRESSION_NONE):
            return cbuffer

        else:
            raise RuntimeError(
                "Unable to process compression %s" % self.compression)


# This class implements Evimetry's AFF4 pre standardisation effort
class AFF4PreSImage(AFF4Image):
    def _get_block_hash_urn(self, bevy_id, hash_datatype):
        return self.urn.Append("%08d/blockHash.%s" % (
            bevy_id, hashes.toShortAlgoName(hash_datatype)))

    def readBlockHash(self, chunk_id, hash_datatype):
        bevy_id = old_div(chunk_id, self.chunks_per_segment)
        bevy_blockHash_urn = self._get_block_hash_urn(
            bevy_id, hash_datatype)
        blockLength = hashes.length(hash_datatype)

        with self.resolver.AFF4FactoryOpen(
                bevy_blockHash_urn) as bevy_blockHashes:
            idx = chunk_id * blockLength

            bevy_blockHashes.SeekRead(idx)
            hash_value = bevy_blockHashes.Read(blockLength)

            return hashes.newImmutableHash(
                binascii.hexlify(hash_value), hash_datatype)


class AFF4SImage(AFF4PreSImage):
    def _get_block_hash_urn(self, bevy_id, hash_datatype):
        return self.urn.Append("%08d.blockHash.%s" % (
            bevy_id, hashes.toShortAlgoName(hash_datatype)))

    def _write_bevy_index(self, volume, bevy_urn, bevy_index, flush=False):
        """Write the index segment for the specified bevy_urn."""
        bevy_index_urn = rdfvalue.URN("%s.index" % bevy_urn)
        if LOGGER.isEnabledFor(logging.INFO):
            LOGGER.info("Writing Bevy Index %s entries=%x", bevy_index_urn, len(bevy_index))

        with volume.CreateMember(bevy_index_urn) as bevy_index_segment:
            serialized_index = b"".join((struct.pack("<QI", offset, length)
                                         for offset, length in bevy_index))
            bevy_index_segment.Write(serialized_index)

            if self.bevy_is_loaded_from_disk and not self.bevy_size_has_changed:
                # no need to flush the bevy
                bevy_index_segment._dirty = False
            if flush:
                #self.resolver.Close(bevy_index_segment)
                bevy_index_segment.FlushAndClose()


    def _parse_bevy_index(self, bevy):
        bevy_index_urn = rdfvalue.URN("%s.index" % bevy.urn)
        with self.resolver.AFF4FactoryOpen(bevy_index_urn) as bevy_index:
            bevy_index_data = bevy_index.Read(bevy_index.Size())
            number_of_entries = bevy_index.Size() // struct.calcsize("QI")
            format_string = "<" + "QI" * number_of_entries
            data = struct.unpack(format_string, bevy_index_data)

            res = [(data[2*i], data[2*i+1]) for i in range(len(data)//2)]
            if LOGGER.isEnabledFor(logging.INFO):
                LOGGER.info("Parse Bevy Index %s size=%x entries=%x", bevy_index_urn, bevy_index.Size(), len(res))
            return res


registry.AFF4_TYPE_MAP[lexicon.AFF4_SCUDETTE_IMAGE_TYPE] = AFF4Image
registry.AFF4_TYPE_MAP[lexicon.AFF4_LEGACY_IMAGE_TYPE] = AFF4PreSImage
registry.AFF4_TYPE_MAP[lexicon.AFF4_IMAGE_TYPE] = AFF4SImage
