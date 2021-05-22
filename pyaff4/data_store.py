# Copyright 2014 Google Inc. All rights reserved.
# Copyright 2018 Schatz Forensic Pty. Ltd. All rights reserved.
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

from __future__ import print_function
from __future__ import unicode_literals

from builtins import str
from builtins import object
from os.path import expanduser
import collections
import logging
import rdflib
import re
import six
import os
import tempfile
import traceback
import subprocess
import sys
import types
import binascii

from rdflib import URIRef
from itertools import chain

from pyaff4 import aff4
from pyaff4 import lexicon
from pyaff4 import rdfvalue
from pyaff4 import registry
from pyaff4 import stream_factory
from pyaff4 import utils
from pyaff4 import streams
from pyaff4 import aff4_map
from pyaff4 import aff4_image, encrypted_stream
from pyaff4 import escaping
from pyaff4 import turtle, hexdump
from pyaff4.zip import ZIP_DEFLATE, ZIP_STORED
from pyaff4.lexicon import transient_graph, XSD_NAMESPACE, any
from pyaff4.aff4_map import isByteRangeARN

LOGGER = logging.getLogger("pyaff4")
HAS_HDT = False
try:
    import hdt
    from hdt import HDTDocument
    HAS_HDT = True
except:
    pass

# Coerce rdflib to use
rdflib.term._toPythonMapping[URIRef(XSD_NAMESPACE + 'hexBinary')] = lambda s: binascii.unhexlify(s)

#HAS_HDT = False
def CHECK(condition, error):
    if not condition:
        raise RuntimeError(error)

class AFF4ObjectCacheEntry(object):
    def __init__(self, key, aff4_obj):
        self.next = self.prev = self
        self.key = key
        self.aff4_obj = aff4_obj
        self.use_count = 0

    def unlink(self):
        self.next.prev = self.prev
        self.prev.next = self.next
        self.next = self.prev = self

    def append(self, entry):
        CHECK(entry.next == entry.prev,
              "Appending an element already in the list")
        entry.next = self.next

        self.next.prev = entry

        entry.prev = self
        self.next = entry

    def __iter__(self):
        entry = self.next
        while entry != self:
            yield entry
            entry = entry.next


class AFF4ObjectCache(object):
    def __init__(self, max_items):
        self.max_items = max_items
        self.in_use = {}
        self.lru_map = {}
        self.lru_list = AFF4ObjectCacheEntry(None, None)
        self.volume_file_map = {}

    def _Trim(self, size=None):
        max_items = size or self.max_items
        while len(self.lru_map) > max_items:
            older_item = self.lru_list.prev
            #LOGGER.debug("Trimming %s from cache" % older_item.key)

            self.lru_map.pop(older_item.key)
            older_item.unlink()

            # Ensure we flush the trimmed objects.
            older_item.aff4_obj.Flush()

    def Put(self, aff4_obj, in_use_state=False):
        if type(aff4_obj) == aff4_map.ByteRangeARN:
            return
        key = aff4_obj.urn.SerializeToString()
        #LOGGER.debug("Putting %s in cache" % key)
        CHECK(key not in self.in_use,
              u"Object %s Put in cache while already in use." % utils.SmartUnicode(key))

        CHECK(key not in self.lru_map,
              u"Object %s Put in cache while already in cache." % utils.SmartUnicode(key))

        entry = AFF4ObjectCacheEntry(key, aff4_obj)
        if in_use_state:
            entry.use_count = 1
            self.in_use[key] = entry
            return

        self.lru_list.append(entry)
        self.lru_map[key] = entry

        self._Trim()

    def Contains(self, urn):
        key = rdfvalue.URN(urn).SerializeToString()
        entry = self.in_use.get(key)
        if entry is not None:
            return True

        entry = self.lru_map.get(key)
        if entry is not None:
            return True
        return False

    def Get(self, urn):
        key = rdfvalue.URN(urn).SerializeToString()
        #LOGGER.debug("Getting %s from cache" % key)
        entry = self.in_use.get(key)
        if entry is not None:
            entry.use_count += 1
            return entry.aff4_obj

        # Hold onto the entry.
        entry = self.lru_map.pop(key, None)
        if entry is None:
            return None

        entry.use_count = 1

        # Remove it from the LRU list.
        entry.unlink()
        self.in_use[key] = entry

        return entry.aff4_obj

    def Return(self, aff4_obj):
        if type(aff4_obj) == aff4_image.AFF4SImage:
            print
        if type(aff4_obj) == aff4_map.ByteRangeARN:
            return
        key = aff4_obj.urn.SerializeToString()
        #LOGGER.debug("Returning %s in cache" % key)
        entry = self.in_use.get(key)
        CHECK(entry is not None,
              u"Object %s Returned to cache, but it is not in use!" % key)
        CHECK(entry.use_count > 0,
              u"Returned object %s is not used." % key)

        entry.use_count -= 1
        if entry.use_count == 0:
            self.lru_list.append(entry)
            self.lru_map[key] = entry
            self.in_use.pop(key)

            self._Trim()

    def Remove(self, aff4_obj):
        if type(aff4_obj) == aff4_image.AFF4SImage:
            print
        key = aff4_obj.urn.SerializeToString()
        #LOGGER.debug("Removing %s in cache" % key)
        entry = self.lru_map.pop(key, None)
        if entry is not None:
            entry.unlink()
            entry.aff4_obj.Flush()
            return

        # Is the item in use?
        entry = self.in_use.pop(key, None)
        if entry is not None:
            entry.unlink()
            entry.aff4_obj.Flush()
            return

        CHECK(False,
              "Object %s removed from cache, but was never there." % key)

    def Dump(self):
        # Now dump the objects in use.
        print("Objects in use:")
        for key, entry in list(self.in_use.items()):
            print(u"%s - %s" % (utils.SmartUnicode(key), entry.use_count))

        print("Objects in cache:")
        for entry in self.lru_list:
            print(u"%s - %s" % (utils.SmartUnicode(entry.key), entry.use_count))

    def Flush(self, partial=False):
        # It is an error to flush the object cache while there are still items
        # in use.
        if not partial and len(self.in_use):
            self.Dump()
            CHECK(len(self.in_use) == 0,
                  "ObjectCache flushed while some objects in use!")

        # First flush all objects without deleting them since some flushed
        # objects may still want to use other cached objects. It is also
        # possible that new objects are added during object deletion. Therefore
        # we keep doing it until all objects are clean.
        while 1:
            dirty_objects_found = False

            for it in self.lru_list:
                if it.aff4_obj.IsDirty():
                    dirty_objects_found = True
                    LOGGER.debug("Flushing %s in cache" % it.key)
                    it.aff4_obj.Flush()

            if not dirty_objects_found:
                break

        if partial:
            return

        # Now delete all entries.
        for it in list(self.lru_map.values()):
            aff4o = it.aff4_obj
            LOGGER.debug("Closing %s in cache" % it.key)
            aff4o.Close()
            it.unlink()


        # Clear the map.
        self.lru_map.clear()

class MemoryDataStore(object):
    aff4NS = None

    def __init__(self, lex=lexicon.standard, parent=None):
        self.lexicon = lex
        self.loadedVolumes = []
        self.store = collections.OrderedDict()
        self.transient_store = collections.OrderedDict()
        if parent == None:
            self.ObjectCache = AFF4ObjectCache(10)
        else:
            self.ObjectCache = parent.ObjectCache
        self.flush_callbacks = {}
        self.parent = parent

        if self.lexicon == lexicon.legacy:
            self.streamFactory = stream_factory.PreStdStreamFactory(
                self, self.lexicon)
        else:
            self.streamFactory = stream_factory.StdStreamFactory(
                self, self.lexicon)


    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, tb):
        try:
            self.Flush()
        except:
            traceback.print_exc()
        if exc_type != None:
            return False

    def Flush(self):
        # Flush and expunge the cache.
        if self.parent == None:
            self.ObjectCache.Flush()
        else:
            self.ObjectCache.Flush(partial=True)
        for cb in list(self.flush_callbacks.values()):
            cb()

    def DeleteSubject(self, subject):
        self.store.pop(rdfvalue.URN(subject), None)

    def CacheContains(self, arn):
        return self.ObjectCache.Contains(arn)

    def CacheGet(self, urn):
        result = self.ObjectCache.Get(urn)
        if result == None:
            return result
        else:
            return result
        #if result is None:
        #    result = aff4.NoneObject("Not present")

        #return result

    def CachePut(self, obj):
        self.ObjectCache.Put(obj, True)
        return obj

    def Return(self, obj):
        #LOGGER.debug("Returning %s" % obj.urn)
        if obj.closed:
            self.Close(obj)
        else:
            self.ObjectCache.Return(obj)

    def Close(self, obj):
        self.ObjectCache.Remove(obj)

    def _should_ignore(self, subject, predicate, object):

        if predicate == lexicon.AFF4_TYPE:
            if object == lexicon.AFF4_ZIP_SEGMENT_TYPE or object == lexicon.AFF4_ZIP_TYPE:
                return True
            else:
                return False

        if predicate == lexicon.AFF4_STORED:
            if not str(object).startswith(u"aff4://"):
                return True
            elif subject.startswith(object.SerializeToString()):
                return True

        return False

    def DumpToTurtle(self, zipcontainer, ):
        infoARN = escaping.urn_from_member_name(u"information.turtle", zipcontainer.urn, zipcontainer.version)
        mode = self.GetUnique(lexicon.transient_graph, zipcontainer.backing_store_urn, lexicon.AFF4_STREAM_WRITE_MODE)
        if mode == "random":
            # random mode is used for appending to encrypted streams, where the stream size changes
            # snapshot mode creates the situation where we have multiple versions of the stream object
            # mashed together, and we cant tell the most recent
            turtle_append_mode="latest"
        else:
            # in append mode, we assume that each time we append, we are adding to the container, rather
            # than modifying any existing objects in the container. Because of this, we get to save multiple
            # independent copies of the turtle from each run, and join them together as text for efficiency
            turtle_append_mode="snapshot"

        if not zipcontainer.ContainsMember(infoARN):
            with zipcontainer.CreateZipSegment(u"information.turtle") as turtle_segment:
                turtle_segment.compression_method = ZIP_STORED

                result = self._DumpToTurtle(zipcontainer.urn)
                turtle_segment.write(utils.SmartStr(result))
                turtle_segment.Flush()
            turtle_segment.Close()
        else:
            # append to an existng container
            self.invalidateCachedMetadata(zipcontainer)
            if turtle_append_mode == "latest":
                zipcontainer.RemoveMember(infoARN)
                with zipcontainer.CreateZipSegment(u"information.turtle") as turtle_segment:
                    turtle_segment.compression_method = ZIP_STORED

                    result = self._DumpToTurtle(zipcontainer.urn)
                    turtle_segment.write(utils.SmartStr(result))
                    turtle_segment.Flush()
                turtle_segment.Close()
                return

            explodedTurtleDirectivesARN = escaping.urn_from_member_name(u"information.turtle/directives", zipcontainer.urn, zipcontainer.version)
            if not zipcontainer.ContainsMember(explodedTurtleDirectivesARN):
                # this is the first append operation. Create the chunked turtle structures
                with zipcontainer.OpenZipSegment(u"information.turtle") as turtle_segment:
                    currentTurtleBytes= streams.ReadAll(turtle_segment)
                    currentturtle = utils.SmartUnicode(currentTurtleBytes)
                    #hexdump.hexdump(currentTurtleBytes)
                    (directives_txt, triples_txt) = turtle.toDirectivesAndTripes(currentturtle)
                    with zipcontainer.CreateZipSegment(u"information.turtle/directives") as directives_segment:
                        directives_segment.compression_method = ZIP_DEFLATE
                        directives_segment.write(utils.SmartStr(directives_txt))
                        directives_segment.Flush()
                    directives_segment.Close()
                    with zipcontainer.CreateZipSegment(u"information.turtle/%08d" % 0) as turtle_chunk_segment:
                        turtle_chunk_segment.compression_method = ZIP_DEFLATE
                        turtle_chunk_segment.write(utils.SmartStr(triples_txt))
                        turtle_chunk_segment.Flush()
                    self.Close(turtle_chunk_segment)
                turtle_segment.Close()

                (current_directives_txt, current_triples_txt) = turtle.toDirectivesAndTripes(utils.SmartUnicode(self._DumpToTurtle(zipcontainer.urn)))
                directives_difference = turtle.difference(directives_txt, current_directives_txt)
                if not len(directives_difference) == 0:
                    directives_txt = directives_txt + u"\r\n" + directives_difference
                    with zipcontainer.CreateZipSegment(u"information.turtle/directives") as directives_segment:
                        directives_segment.compression_method = ZIP_DEFLATE
                        directives_segment.write(utils.SmartStr(directives_txt))
                        directives_segment.Flush()
                    directives_segment.Close()

                current_turtle_chunk_arn = rdfvalue.URN(u"%s/information.turtle/%08d" % (zipcontainer.urn, 1))
                with zipcontainer.CreateMember(current_turtle_chunk_arn) as turtle_segment:
                    turtle_segment.compression_method = ZIP_DEFLATE
                    turtle_segment.write(utils.SmartStr(current_triples_txt))
                    turtle_segment.Flush()
                self.Close(turtle_segment)

                zipcontainer.RemoveSegment(u"information.turtle")
                with zipcontainer.CreateZipSegment(u"information.turtle") as turtle_segment:
                    turtle_segment.compression_method = ZIP_STORED
                    turtle_segment.write(utils.SmartStr(directives_txt + "\r\n\r\n"))

                    turtleContainerIndex = 0
                    while True:
                        current_turtle_chunk_arn = rdfvalue.URN(u"%s/information.turtle/%08d" % (zipcontainer.urn, turtleContainerIndex))

                        if zipcontainer.ContainsMember(current_turtle_chunk_arn):
                            with zipcontainer.OpenMember(current_turtle_chunk_arn) as turtle_chunk_segment:
                                turtle_chunk_txt = utils.SmartUnicode(streams.ReadAll(turtle_chunk_segment))
                                turtle_segment.write(utils.SmartStr(turtle_chunk_txt + u"\r\n"))
                            turtleContainerIndex += 1

                        else:
                            break
                    turtle_segment.Flush()
                turtle_segment.Close()
            else:
                # more than one append as already occurred
                turtleContainerIndex = 0
                while True:
                    turtleARN = escaping.urn_from_member_name(u"information.turtle/%08d" % turtleContainerIndex,
                                                                                zipcontainer.urn, zipcontainer.version)
                    if not zipcontainer.ContainsMember(turtleARN):
                        break
                    turtleContainerIndex = turtleContainerIndex + 1

                with zipcontainer.OpenZipSegment(u"information.turtle/directives") as directives_segment:
                    directives_txt = utils.SmartUnicode(streams.ReadAll(directives_segment))

                (current_directives_txt, current_triples_txt) = turtle.toDirectivesAndTripes(utils.SmartUnicode(self._DumpToTurtle(zipcontainer.urn)))
                directives_difference = turtle.difference(directives_txt, current_directives_txt)

                if len(directives_difference) > 0:
                    directives_txt = directives_txt + u"\r\n" + u"\r\n".join(directives_difference)
                    with zipcontainer.CreateZipSegment(u"information.turtle/directives") as directives_segment:
                        directives_segment.compression_method = ZIP_DEFLATE
                        directives_segment.write(utils.SmartStr(directives_txt))
                        directives_segment.Flush()
                    directives_segment.Close()

                with zipcontainer.CreateZipSegment(u"information.turtle/%08d" % turtleContainerIndex) as turtle_segment:
                    turtle_segment.compression_method = ZIP_DEFLATE
                    turtle_segment.write(utils.SmartStr(current_triples_txt))
                    turtle_segment.Flush()
                turtle_segment.Close()

                with zipcontainer.CreateZipSegment(u"information.turtle") as turtle_segment:
                    turtle_segment.compression_method = ZIP_DEFLATE
                    turtle_segment.write(utils.SmartStr(directives_txt + u"\r\n\r\n"))

                    turtleContainerIndex = 0
                    while True:
                        turtleARN = escaping.urn_from_member_name(u"information.turtle/%08d" % turtleContainerIndex,
                                                                  zipcontainer.urn, zipcontainer.version)
                        if zipcontainer.ContainsMember(turtleARN):
                            with zipcontainer.OpenZipSegment(
                                u"information.turtle/%08d" % turtleContainerIndex) as turtle_chunk_segment:
                                turtle_chunk_txt = utils.SmartUnicode(streams.ReadAll(turtle_chunk_segment))
                                turtle_segment.write(utils.SmartStr(turtle_chunk_txt + u"\r\n"))
                            turtleContainerIndex += 1
                        else:
                            break
                    turtle_segment.Flush()
                turtle_segment.Close()

    def _DumpToTurtle(self, volumeurn, verbose=False):
        g = rdflib.Graph()
        g.bind("aff4", rdflib.Namespace(self.lexicon.base))

        # looks like rdflib has some problems with re-constituting subjects using @base
        # comment out for now
        #volumeNamespace = rdflib.Namespace(volumeurn.value + "/")
        #volumeBase = volumeurn.value + "/"

        for urn, items in self.store.items():
            urn = utils.SmartUnicode(urn)
            type = items.get(utils.SmartUnicode(lexicon.AFF4_TYPE))

            # only dump objects and pseudo map entries
            if type is None:
                if not urn.startswith(u"aff4:sha512:"):
                    continue

            for attr, value in list(items.items()):
                attr = utils.SmartUnicode(attr)
                # We suppress certain facts which can be deduced from the file
                # format itself. This ensures that we do not have conflicting
                # data in the data store. The data in the data store is a
                # combination of explicit facts and implied facts.
                if not verbose:
                    if attr.startswith(lexicon.AFF4_VOLATILE_NAMESPACE):
                        continue

                if not isinstance(value, list):
                    value = [value]

                for item in value:
                    if self._should_ignore(urn, attr, item):
                        continue
                    g.add((rdflib.URIRef(urn), rdflib.URIRef(attr), item.GetRaptorTerm()))

        #result = g.serialize(format='turtle', base=volumeNamespace)
        result = g.serialize(format='turtle')
        result = utils.SmartUnicode(result)
        #basestart = "@base <%s> .\r\n" % (volumeBase)
        #result = basestart + result

        return result

    def loadMetadata(self, zip):
        # Load the turtle metadata.
        #if zip.urn not in self.loadedVolumes:
        with zip.OpenZipSegment("information.turtle") as fd:
            self.LoadFromTurtle(fd, zip.urn)
            self.loadedVolumes.append(zip.urn)

    def LoadFromTurtle(self, stream, volume_arn):
        data = streams.ReadAll(stream)
        g = rdflib.Graph()
        g.parse(data=data, format="turtle")

        for urn, attr, value in g:
            urn = utils.SmartUnicode(urn)
            attr = utils.SmartUnicode(attr)
            serialized_value = value

            if isinstance(value, rdflib.URIRef):
                value = rdfvalue.URN(utils.SmartUnicode(serialized_value))
            elif value.datatype in registry.RDF_TYPE_MAP:
                dt = value.datatype
                value = registry.RDF_TYPE_MAP[value.datatype](
                    serialized_value)

            else:
                # Default to a string literal.
                value = rdfvalue.XSDString(value)

            if attr == rdfvalue.URN(lexicon.AFF4_TYPE) and value == rdfvalue.URN(lexicon.AFF4_IMAGE_TYPE):
                self.Add(lexicon.transient_graph, urn, lexicon.AFF4_STORED, volume_arn)
            self.Add(volume_arn, urn, attr, value)

        # look for the AFF4 namespace defined in the turtle
        for (_, b) in g.namespace_manager.namespaces():
            if (str(b) == lexicon.AFF4_NAMESPACE or
                str(b) == lexicon.AFF4_LEGACY_NAMESPACE):
                self.aff4NS = b

    def AFF4FactoryOpen(self, urn, version=None):
        urn = rdfvalue.URN(urn)

        # Is the object cached?
        cached_obj = self.ObjectCache.Get(urn)
        if cached_obj:
            cached_obj.Prepare()
            #LOGGER.debug("AFF4FactoryOpen (Cached): %s" % urn)
            return cached_obj

        if self.streamFactory.isSymbolicStream(urn):
            obj = self.streamFactory.createSymbolic(urn)
        elif urn.SerializeToString().startswith("aff4:sha512"):
            # Don't use the cache for these as they are low cost
            # and they will push aside heavier weight things
            #bytestream_reference_id = self.Get(urn, urn, rdfvalue.URN(lexicon.standard.dataStream))
            #cached_obj = self.ObjectCache.Get(bytestream_reference_id)
            #if cached_obj:
            #    cached_obj.Prepare()
            #    return cached_obj
            bytestream_reference_id = self.GetUnique(lexicon.any, urn, rdfvalue.URN(lexicon.standard.dataStream))
            return aff4_map.ByteRangeARN(version, resolver=self, urn=bytestream_reference_id)
        elif isByteRangeARN(urn.SerializeToString()):
            return aff4_map.ByteRangeARN(version, resolver=self, urn=urn)
        else:
            uri_types = self.Get(lexicon.any, urn, rdfvalue.URN(lexicon.AFF4_TYPE))

            handler = None

            # TODO: this could be cleaner. RDF properties have multiple values

            if isinstance(uri_types, list) or isinstance(uri_types, types.GeneratorType):
                for typ in uri_types:
                    handler = registry.AFF4_TYPE_MAP.get(typ)
                    if handler is not None:
                        break
            else:
                handler = registry.AFF4_TYPE_MAP.get(uri_types)

            if handler is None:
                # Try to instantiate the handler based on the URN scheme alone.
                components = urn.Parse()
                handler = registry.AFF4_TYPE_MAP.get(components.scheme)

            if handler is None and self.parent != None:
                # try the parent
                o = self.parent.AFF4FactoryOpen(urn)
                if o != None:
                    return o


            if handler is None:
                raise IOError("Unable to create object %s" % urn)

            obj = handler(resolver=self, urn=urn, version=version)
            obj.LoadFromURN()

        # Cache the object for next time.
        self.ObjectCache.Put(obj, True)

        #LOGGER.debug("AFF4FactoryOpen (new instance): %s" % urn)
        obj.Prepare()
        return obj

    def Dump(self, verbose=False):
        print(utils.SmartUnicode(self.DumpToTurtle(verbose=verbose)))
        self.ObjectCache.Dump()

    def isImageStream(self, subject):
        try:
            po = self.store[subject]
            if po == None:
                return False
            else:
                o = po[lexicon.AFF4_TYPE]
                if o == None:
                    return False
                else:
                    if type(o) == type([]):
                        for ent in o:
                            if ent.value == lexicon.AFF4_LEGACY_IMAGE_TYPE or ent.value == lexicon.AFF4_IMAGE_TYPE :
                                return True
                        return False
                    else:
                        if o.value == lexicon.AFF4_LEGACY_IMAGE_TYPE or o.value == lexicon.AFF4_IMAGE_TYPE :
                            return True
                        else:
                            return False
        except:
            return False

    # FIXME: This is a big API breaking change - we simply can not
    # change the type we are returning from Get() depending on random
    # factors. We need to make the store _always_ hold a list for all
    # members.
    def Add(self, graph, subject, attribute, value):
        subject = rdfvalue.URN(subject).SerializeToString()
        attribute = rdfvalue.URN(attribute).SerializeToString()
        CHECK(isinstance(value, rdfvalue.RDFValue), "Value must be an RDFValue")

        if graph == transient_graph:
            store = self.transient_store
        else:
            store = self.store

        if attribute not in store.setdefault(
                subject, collections.OrderedDict()):
            store.get(subject)[attribute] = value
        else:
            oldvalue = store.get(subject)[attribute]
            t = type(oldvalue)
            if  t != type([]):
                if value != oldvalue:
                    store.get(subject)[attribute] = [oldvalue, value]
            else:
                if value not in oldvalue:
                    oldvalue.append(value)


    def Set(self, graph, subject, attribute, value):
        subject = rdfvalue.URN(subject).SerializeToString()
        attribute = rdfvalue.URN(attribute).SerializeToString()
        CHECK(isinstance(value, rdfvalue.RDFValue), "Value must be an RDFValue")

        if graph == transient_graph:
            store = self.transient_store
        else:
            store = self.store

        store.setdefault(subject, {})[attribute] = value

    # return a list of results
    def Get(self, graph, subject, attribute):
        subject = rdfvalue.URN(subject).SerializeToString()
        attribute = rdfvalue.URN(attribute).SerializeToString()

        if graph == lexicon.any or graph == None:
            resa = self.transient_store.get(subject, {}).get(attribute)
            resb = self.store.get(subject, {}).get(attribute)
            return utils.asList(resa, resb)

        elif graph == transient_graph:
            res = self.transient_store.get(subject, {}).get(attribute)
            if isinstance(res, list):
                return res
            else:
                return [res]
        else:
            res = self.store.get(subject, {}).get(attribute)
            if isinstance(res, list):
                return res
            else:
                return [res]

    # return a single result or None
    def GetUnique(self, graph, subject, attribute):
        res = self.Get(graph, subject, attribute)
        if isinstance (res, list):
            if len(res) == 1:
                return res[0]
            return None
        elif isinstance(res, types.GeneratorType):
            return list(res)
        else:
            return res

    def QuerySubject(self, graph, subject_regex=None):
        subject_regex = re.compile(utils.SmartStr(subject_regex))

        if graph == lexicon.any or graph == None:
            storeitems = chain(six.iteritems(self.store), six.iteritems(self.transient_store))
        elif graph == transient_graph:
            storeitems = six.iteritems(self.transient_store)
        else:
            storeitems = six.iteritems(self.store)

        for subject in storeitems:
            if subject_regex is not None and subject_regex.match(subject):
                yield rdfvalue.URN().UnSerializeFromString(subject)

    def QueryPredicate(self, graph, predicate):
        """Yields all subjects which have this predicate."""
        predicate = utils.SmartStr(predicate)

        if graph == lexicon.any or graph == None:
            storeitems = chain(six.iteritems(self.store), six.iteritems(self.transient_store))
        elif graph == transient_graph:
            storeitems = six.iteritems(self.transient_store)
        else:
            storeitems = six.iteritems(self.store)

        for subject, data in storeitems:
            for pred, values in six.iteritems(data):
                if pred == predicate:
                    if type(values) != type([]):
                        values = [values]
                    for value in values:
                        yield (rdfvalue.URN().UnSerializeFromString(subject),
                               rdfvalue.URN().UnSerializeFromString(predicate),
                               value)


    def QueryPredicateObject(self, graph, predicate, object):
        predicate = utils.SmartUnicode(predicate)

        if graph == lexicon.any or graph == None:
            storeitems = chain(six.iteritems(self.store), six.iteritems(self.transient_store))
        elif graph == transient_graph:
            storeitems = six.iteritems(self.transient_store)
        else:
            storeitems = six.iteritems(self.store)

        for subject, data in list(storeitems):
            for pred, value in list(data.items()):
                if pred == predicate:
                    if type(value) != type([]):
                        value = [value]

                    if object in value:
                        yield rdfvalue.URN(subject)

    def QuerySubjectPredicateInternal(self, store, subject, predicate):
        if subject in store:
            predicateValues = store[subject]
            if predicate in predicateValues:
                storeValues = predicateValues[predicate]
                if type(storeValues) != type([]):
                    yield storeValues
                else:
                    for val in storeValues:
                        yield val


    def QuerySubjectPredicate(self, graph, subject, predicate):
        if isinstance(subject, rdfvalue.URN):
            subject = subject.SerializeToString()
        else:
            subject = utils.SmartUnicode(subject)

        if isinstance(predicate, rdfvalue.URN):
            predicate = predicate.SerializeToString()
        else:
            predicate = utils.SmartUnicode(predicate)

        if graph == lexicon.any or graph == None:
            for val in self.QuerySubjectPredicateInternal(self.transient_store, subject, predicate):
                yield val
            for val in self.QuerySubjectPredicateInternal(self.store, subject, predicate):
                yield val
        elif graph == transient_graph:
            for val in self.QuerySubjectPredicateInternal(self.transient_store, subject, predicate):
                yield val
        else:
            for val in self.QuerySubjectPredicateInternal(self.store, subject, predicate):
                yield val


    def SelectSubjectsByPrefix(self, graph, prefix):
        prefix = utils.SmartUnicode(prefix)

        if graph == lexicon.any or graph == None:
            storeitems = chain(six.iteritems(self.store), six.iteritems(self.transient_store))
        elif graph == transient_graph:
            storeitems = six.iteritems(self.transient_store)
        else:
            storeitems = six.iteritems(self.store)

        for subject, predicateDict in storeitems:
            if subject.startswith(prefix):
                yield rdfvalue.URN(subject)

    def QueryPredicatesBySubject(self, graph, subject):
        subject = utils.SmartUnicode(subject)

        if graph == transient_graph:
            store = self.transient_store
        else:
            store = self.store

        for pred, value in list(store.get(subject, {}).items()):
            yield (rdfvalue.URN().UnSerializeFromString(pred), value)

    def invalidateCachedMetadata(self, zip):
        pass

# With large information.turtle files, the in-memory database performs
# horribly. This is a faster way. http://www.rdfhdt.org
class HDTAssistedDataStore(MemoryDataStore):
    def __init__(self, lex=lexicon.standard):
        super(HDTAssistedDataStore, self).__init__(lex=lex)
        self.hdt = None

    def invalidateCachedMetadata(self, zip):
        aff4cache = os.path.join(expanduser("~"), ".aff4")
        cached_turtle = os.path.join(aff4cache, "%s.hdt" % str(zip.urn)[7:])
        cached_turtle_index = cached_turtle + ".index.v1-1"
        for f in [cached_turtle, cached_turtle_index]:
            if os.path.exists(f):
                LOGGER.debug("Invalidating HDT index %s" % f)
                os.unlink(f)

    def createHDTviaLib(self, zip, cached_turtle):
        try:
            temp = tempfile.NamedTemporaryFile(delete=False)
            LOGGER.debug("Creating HDT index %s" % cached_turtle)
            LOGGER.debug("Creating temp turtle file for import %s" % temp.name)
            try:
                with zip.OpenZipSegment("information.turtle") as fd:
                    streams.WriteAll(fd, temp)
                temp.close()
            except Exception as e:
                # no turtle yet
                return

            doc = hdt.generate_hdt(temp.name, "aff4://foo")
            retcode = doc.save_to_hdt(cached_turtle)

            if retcode != 0:
                print("rdf2hdt failed", -retcode, file=sys.stderr)
            else:
                pass

        except:
            traceback.print_exc()
            raise Exception("rdf2dht failed. Please make data_store.HAS_HDT=False until this is fixed. ")

        finally:
            os.unlink(temp.name)


    def loadMetadata(self, zip):
        # Load the turtle metadata.
        aff4cache = os.path.join(expanduser("~"), ".aff4")
        if not os.path.exists(aff4cache):
            try:
                os.makedirs(aff4cache)
            except OSError as exc:  # Guard against race condition
                if exc.errno != errno.EEXIST:
                    raise
        cached_turtle = os.path.join(aff4cache, "%s.hdt" % str(zip.urn)[7:])
        if not os.path.exists(cached_turtle):
            self.createHDTviaLib(zip, cached_turtle)

        if os.path.exists(cached_turtle):
            # assume we have a HDT cache of turtle at this point
            self.hdt = HDTDocument(cached_turtle)


    # this implementation currently not tested
    # and it is super ugly. We are materializing all triples just to
    # list all the subjects.
    # TODO: Implement subject iterator in pyHDT
    def QuerySubject(self, graph, subject_regex=None):
        if graph == transient_graph:
            yield super(HDTAssistedDataStore, self).QuerySubject(transient_graph, subject_regex)

        subject_regex = re.compile(utils.SmartStr(subject_regex))
        (triples, cardinality) = self.hdt.search_triples("", "?", "?")
        seen_subject = []

        for (s,p,o) in triples:
            if subject_regex is not None and subject_regex.match(s):
                if s not in seen_subject:
                    seen_subject.add(s)
                    yield rdfvalue.URN().UnSerializeFromString(s)

        for s in super(HDTAssistedDataStore, self).QuerySubject(graph, subject_regex=subject_regex):
            if s not in seen_subject:
                seen_subject.add(s)
                yield s

    # not yet implemented
    def QueryPredicate(self, graph, predicate):
        if graph == transient_graph:
            yield super(HDTAssistedDataStore, self).QueryPredicate(transient_graph, predicate)

        yield super(HDTAssistedDataStore, self).QueryPredicate(graph, predicate)

    def QueryPredicateObject(self, graph, predicate, object):
        (triples, cardinality) = self.hdt.search_triples("", predicate, object)

        for (s,p,o) in triples:
            yield rdfvalue.URN(s)

        for subject in super(HDTAssistedDataStore, self).QueryPredicateObject(graph, predicate, object):
            yield subject

    def Get(self, graph, subject, attribute):
        if self.hdt == None:
            return super(HDTAssistedDataStore, self).Get(graph, subject, attribute)
        else:
            # we use a set here as we some implementations might pass up an object from
            # the persisted graph and the transient graph. The set lets us remove duplicates
            res = set(self.QuerySubjectPredicate(graph, subject, attribute))
            if len(res) == 1:
                return list(res)
            return list(res)

    def QuerySubjectPredicate(self, graph, subject, predicate):
        for o in super(HDTAssistedDataStore, self).QuerySubjectPredicate(graph, subject, predicate):
            yield o

        if self.hdt == None:
            return

        if graph == transient_graph:
            return

        if isinstance(subject, rdfvalue.URN):
            subject = subject.SerializeToString()
        else:
            subject = utils.SmartUnicode(subject)

        if isinstance(predicate, rdfvalue.URN):
            predicate = predicate.SerializeToString()
        else:
            predicate = utils.SmartUnicode(predicate)

        (triples, cardinality) = self.hdt.search_triples(subject, predicate, "")

        for (s,p,o) in triples:
            if o.startswith("\""):
                # it is a literal
                (v,t) = o.split("^^")
                v = v.replace("\"", "")
                t = t[1:len(t)-1]

                datatype = rdflib.URIRef(t)
                if datatype in registry.RDF_TYPE_MAP:
                    o = registry.RDF_TYPE_MAP[datatype](v)
                else:
                    # Default to a string literal.
                    o = rdfvalue.XSDString(v)
            elif o.startswith("<"):
                o = rdfvalue.URN(utils.SmartUnicode(o))
            elif o.startswith("aff4://"):
                o = rdfvalue.URN(utils.SmartUnicode(o))
            else:
                o = rdfvalue.URN(utils.SmartUnicode(o))

            yield o


    def SelectSubjectsByPrefix(self, graph, prefix):
        if graph == transient_graph:
            yield super(HDTAssistedDataStore, self).SelectSubjectsByPrefix(transient_graph, prefix)

        yield super(HDTAssistedDataStore, self).SelectSubjectsByPrefix(graph, prefix)

    def QueryPredicatesBySubject(self, graph, subject):
        if graph == transient_graph:
            yield super(HDTAssistedDataStore, self).QueryPredicatesBySubject(transient_graph, subject)

        yield super(HDTAssistedDataStore, self).QueryPredicatesBySubject(graph, subject)