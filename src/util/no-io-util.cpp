/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/**
* Copyright (c) 2016 Regents of the University of California.
*
* This file is part of the nTorrent codebase.
*
* nTorrent is free software: you can redistribute it and/or modify it under the
* terms of the GNU Lesser General Public License as published by the Free Software
* Foundation, either version 3 of the License, or (at your option) any later version.
*
* nTorrent is distributed in the hope that it will be useful, but WITHOUT ANY
* WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A
* PARTICULAR PURPOSE. See the GNU Lesser General Public License for more details.
*
* You should have received copies of the GNU General Public License and GNU Lesser
* General Public License along with nTorrent, e.g., in COPYING.md file. If not, see
* <http://www.gnu.org/licenses/>.
*
* See AUTHORS for complete list of nTorrent authors and contributors.
*/

//README: This file has been created to eliminate I/O operations for the simulator.
//no-io-util.[ch]pp replaces io-util.[ch]pp
//io-util.cpp has been removed from the build. Edit wscript to include it again


#include "util/io-util.hpp"

#include "file-manifest.hpp"
#include "torrent-file.hpp"
#include "util/logging.hpp"
#include "util/simulation-constants.hpp"

#include <boost/filesystem.hpp>
#include <boost/filesystem/fstream.hpp>

#include <ndn-cxx/security/key-chain.hpp>
#include <ndn-cxx/security/signing-helpers.hpp>

namespace fs = boost::filesystem;

using std::string;
using std::vector;

namespace ndn {
namespace ntorrent {

std::vector<ndn::Data>
IoUtil::packetize_file(const fs::path& filePath,
                       const ndn::Name& commonPrefix,
                       size_t dataPacketSize,
                       size_t subManifestSize,
                       size_t subManifestNum)
{
  BOOST_ASSERT(0 < dataPacketSize);
  size_t APPROX_BUFFER_SIZE = std::numeric_limits<int>::max(); // 2 * 1024 * 1024 *1024
  auto file_size = DUMMY_FILE_SIZE;
  auto start_offset = subManifestNum * subManifestSize * dataPacketSize;
  // determine the number of bytes in this submanifest
  auto subManifestLength = subManifestSize * dataPacketSize;
  auto remainingFileLength = file_size - start_offset;
  subManifestLength = remainingFileLength < subManifestLength
                    ? remainingFileLength
                    : subManifestLength;
  vector<ndn::Data> packets;
  packets.reserve(subManifestLength/dataPacketSize + 1);
  
  // ensure that buffer is large enough to contain whole packets
  // buffer size is either the entire file or the smallest number of data packets >= 2 GB
  auto buffer_size =
    subManifestLength < APPROX_BUFFER_SIZE   ?
    subManifestLength                        :
    APPROX_BUFFER_SIZE % dataPacketSize == 0 ?
    APPROX_BUFFER_SIZE :
    APPROX_BUFFER_SIZE + dataPacketSize - (APPROX_BUFFER_SIZE % dataPacketSize);
  vector<char> file_bytes;
  file_bytes.reserve(buffer_size);
  size_t bytes_read = 0;
  while(bytes_read < subManifestLength) {
    for(uint32_t i=0; i < buffer_size; i++){
        file_bytes.push_back(DUMMY_CHAR);
    }
    auto read_size = buffer_size;
    bytes_read += read_size;
    char *curr_start = &file_bytes.front();
    for (size_t i = 0u; i < buffer_size; i += dataPacketSize) {
      // Build a packet from the data
      Name packetName = commonPrefix;
      packetName.appendSequenceNumber(packets.size());
      Data d(packetName);
      auto content_length = i + dataPacketSize > buffer_size ? buffer_size - i : dataPacketSize;
      d.setContent(encoding::makeBinaryBlock(tlv::Content, curr_start, content_length));
      curr_start += content_length;
      // append to the collection
      packets.push_back(d);
    }
    file_bytes.clear();
    // recompute the buffer_size
    buffer_size =
      subManifestLength - bytes_read < APPROX_BUFFER_SIZE ?
      subManifestLength - bytes_read                      :
      APPROX_BUFFER_SIZE % dataPacketSize == 0            ?
      APPROX_BUFFER_SIZE                                  :
      APPROX_BUFFER_SIZE + dataPacketSize - (APPROX_BUFFER_SIZE % dataPacketSize);
  }
  
  packets.shrink_to_fit();
  ndn::security::KeyChain key_chain;
  // sign all the packets
  for (auto& p : packets) {
    key_chain.sign(p, signingWithSha256());
  }
  return packets;
}

bool IoUtil::writeTorrentSegment(const TorrentFile& segment, const std::string& path)
{
  //always succeed since no file I/O is to be done on the simulation.
  return true;
}

bool IoUtil::writeFileManifest(const FileManifest& manifest, const std::string& path)
{
  //always succeed since no file I/O is to be done on the simulation.
  return true;
}
bool
IoUtil::writeData(const Data&         packet,
                  const FileManifest& manifest,
                  size_t              subManifestSize,
                  const std::string&  filePath)
{
  //always succeed since no file I/O is to be done on the simulation.
  return true;
}

std::shared_ptr<Data>
IoUtil::readDataPacket(const Name&         packetFullName,
                       const FileManifest& manifest,
                       size_t              subManifestSize,
                       const std::string&  filePath)
{
 auto dataPacketSize = manifest.data_packet_size();
 std::vector<char> bytes(dataPacketSize);
 for(uint32_t i=0; i< dataPacketSize; i++)
     bytes.push_back(DUMMY_CHAR);
 auto read_size = dataPacketSize;
 
 // construct packet
 auto packetName = packetFullName.getSubName(0, packetFullName.size() - 1);
 auto d = make_shared<Data>(packetName);
 d->setContent(encoding::makeBinaryBlock(tlv::Content, &bytes.front(), read_size));
 ndn::security::KeyChain key_chain;
 key_chain.sign(*d, signingWithSha256());
 return d->getFullName() == packetFullName ? d : nullptr;
}

IoUtil::NAME_TYPE
IoUtil::findType(const Name& name)
{
  NAME_TYPE rval = UNKNOWN;
  if (name.get(name.size() - 2).toUri() == "torrent-file" ||
      name.get(name.size() - 3).toUri() == "torrent-file") {
    rval = TORRENT_FILE;
  }
  else if (name.get(name.size() - 2).isSequenceNumber() &&
           name.get(name.size() - 3).isSequenceNumber()) {
    rval = DATA_PACKET;
  }
  else if (name.get(name.size() - 2).isSequenceNumber() &&
           !(name.get(name.size() - 3).isSequenceNumber())) {
    rval = FILE_MANIFEST;
  }
  return rval;
}



} // namespace ntorrent
} // namespace ndn
