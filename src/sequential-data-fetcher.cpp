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

#include "sequential-data-fetcher.hpp"
#include "util/logging.hpp"
#include "util/io-util.hpp"

namespace ndn {
namespace ntorrent {

SequentialDataFetcher::SequentialDataFetcher(const ndn::Name&   torrentFileName,
                                             const std::string& dataPath,
                                             bool               seed)
  : m_dataPath(dataPath)
  , m_torrentFileName(torrentFileName)
  , m_seedFlag(seed)
{
  m_manager = make_shared<TorrentManager>(m_torrentFileName, m_dataPath, seed);
}

SequentialDataFetcher::~SequentialDataFetcher()
{
}

void
SequentialDataFetcher::start(const time::milliseconds& timeout)
{
  m_manager->Initialize();
  // downloading logic
  this->implementSequentialLogic();
  m_manager->processEvents(timeout);
}

void
SequentialDataFetcher::pause()
{
  // TODO(Spyros): Implement asyncrhonous pause of the torrent downloading
  // For now, do nothing...
  throw(Error("Not implemented yet"));
}

void
SequentialDataFetcher::resume()
{
  // TODO(Spyros): Implement asyncrhonous re-establishment of the torrent downloading
  // For now, do nothing...
  throw(Error("Not implemented yet"));
}

void
SequentialDataFetcher::downloadTorrentFile()
{
  auto torrentPath = ".appdata/" + m_torrentFileName.get(-3).toUri() + "/torrent_files/";
  m_manager->downloadTorrentFile(torrentPath,
                                 bind(&SequentialDataFetcher::onTorrentFileSegmentReceived, this, _1),
                                 bind(&SequentialDataFetcher::onDataRetrievalFailure, this, _1, _2));
}

void
SequentialDataFetcher::downloadManifestFiles(const std::vector<ndn::Name>& manifestNames)
{
  auto manifestPath = ".appdata/" + m_torrentFileName.get(-3).toUri() + "/manifests/";
  for (auto i = manifestNames.begin(); i != manifestNames.end(); i++) {
    m_manager->download_file_manifest(*i,
                              manifestPath,
                              bind(&SequentialDataFetcher::onManifestReceived, this, _1),
                              bind(&SequentialDataFetcher::onDataRetrievalFailure, this, _1, _2));
  }
}

void
SequentialDataFetcher::downloadPackets(const std::vector<ndn::Name>& packetsName)
{
  for (auto i = packetsName.begin(); i != packetsName.end(); i++) {
    m_manager->download_data_packet(*i,
                              bind(&SequentialDataFetcher::onDataPacketReceived, this, _1),
                              bind(&SequentialDataFetcher::onDataRetrievalFailure, this, _1, _2));
  }
}

void
SequentialDataFetcher::implementSequentialLogic() {
  // TODO(?) Fix seeding, and implement windowing:
  /*
  Alex says look at ndn-cxx:
  * fetcher with queue (with window)
  * segment fetcher ?
  * catchunks (pipeline?)
  */
  if (!m_manager->hasAllTorrentSegments()) {
    this->downloadTorrentFile();
  }
  else {
    LOG_INFO <<  m_torrentFileName << " complete" <<  std::endl;
    std::vector<ndn::Name> namesToFetch;
    m_manager->findFileManifestsToDownload(namesToFetch);
    if (!namesToFetch.empty()) {
      this->downloadManifestFiles(namesToFetch);
    }
    else {
      LOG_INFO << "All manifests complete" <<  std::endl;
      m_manager->findAllMissingDataPackets(namesToFetch);
      if (!namesToFetch.empty()) {
        this->downloadPackets(namesToFetch);
      }
      else {
        LOG_INFO << "All data complete" <<  std::endl;
        if (!m_seedFlag) {
          m_manager->shutdown();
        }
      }
    }
  }
}

void
SequentialDataFetcher::onDataPacketReceived(const ndn::Data& data)
{
  // Data Packet Received
  LOG_INFO << "Data Packet Received: " << data.getName();
}

void
SequentialDataFetcher::onTorrentFileSegmentReceived(const std::vector<Name>& manifestNames)
{
  // TODO(msweatt) Add parameter for torrent file
  LOG_INFO << "Torrent Segment Received: " << m_torrentFileName << std::endl;
  this->downloadManifestFiles(manifestNames);
}

void
SequentialDataFetcher::onManifestReceived(const std::vector<Name>& packetNames)
{
  LOG_INFO << "Manifest File Received: "
            << packetNames[0].getSubName(0, packetNames[0].size()- 3) << std::endl;
  this->downloadPackets(packetNames);
}

void
SequentialDataFetcher::onDataRetrievalFailure(const ndn::Interest& interest,
                                              const std::string& errorCode)
{
  // Data retrieval failure
  uint32_t nameType = IoUtil::findType(interest.getName());
  if (nameType == IoUtil::TORRENT_FILE) {
    // this should never happen
    LOG_ERROR << "Torrent File Segment Downloading Failed: " << interest.getName();
    this->downloadTorrentFile();
  }
  else if (nameType == IoUtil::FILE_MANIFEST) {
    LOG_ERROR << "Manifest File Segment Downloading Failed: " << interest.getName();
    this->downloadManifestFiles({ interest.getName() });
  }
  else if (nameType == IoUtil::DATA_PACKET) {
    LOG_ERROR << "Data Packet Downloading Failed: " << interest.getName();
    this->downloadPackets({ interest.getName() });
  }
  else {
    // This should never happen
    LOG_ERROR << "Unknown Packet Type Downloading Failed: " << interest.getName();
  }
}

} // namespace ntorrent
} // namespace ndn
