/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/**
 * Copyright (c) 2014,  Regents of the University of California
 *
 * This file is part of Simple BT.
 * See AUTHORS.md for complete list of Simple BT authors and contributors.
 *
 * NSL is free software: you can redistribute it and/or modify it under the terms
 * of the GNU General Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 *
 * NSL is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
 * without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR
 * PURPOSE.  See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * NSL, e.g., in COPYING.md file.  If not, see <http://www.gnu.org/licenses/>.
 *
 * \author Yingdi Yu <yingdi@cs.ucla.edu>
 */

#ifndef SBT_CLIENT_HPP
#define SBT_CLIENT_HPP

#include "common.hpp"
#include "shared.hpp"

#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <errno.h> 
#include <netinet/in.h> 
#include <arpa/inet.h> 
#include <string.h>

#include <math.h>


// ??
#include <sys/wait.h>
//#include <sys/sockio.h>
#include <netdb.h>
//#include <netine/tcp.h>
// ??

#include <sstream>
#include <fstream>

#include "meta-info.hpp"

#include "http/http-request.hpp"
#include "http/url-encoding.hpp"
#include "http/http-response.hpp"

#include "util/buffer.hpp"
#include "util/bencoding.hpp"
#include "util/hash.hpp"
#include "util/buffer-stream.hpp"

#include "tracker-response.hpp"

#include "msg/handshake.hpp"
#include "msg/msg-base.hpp"

using namespace std;

namespace sbt {

class Client
{
public:
    // Constructor for client - downloading
    Client(struct shared_vars *shared, PeerInfo peerInfo, int threadID);
    
    // Constructor for server - uploading
    Client(struct shared_vars *shared, int sockFD, int threadID);
    
private:
    struct shared_vars *m_shared;
    
    int m_threadID;
    
    // States
    bool m_isHandshakeReceived;
    
    bool m_isClient;
    bool m_hasHandshaked;
    bool m_hasBitfield;
    bool m_amInterested;
    bool m_amChoking;
    bool m_peerInterested;
    bool m_peerChoking;
    
    int m_currentPieceIndex;
    
    // Peer's info
    int m_sockFD;
    BufferPtr m_peerBitfield;
    PeerInfo m_peerInfo;
    
    // Other
    void initStates();
    
    // Socket
    void setupConnection();
    void closeConnection();
    void sendMsg(void *requestBuffer, size_t requestBufferLength);
    void recvMsg();
    
    // Writing/Reading Logic
    void handshakeMessenger();
    void messenger(uint8_t msgID, int pieceIndex = -1, int pieceBegin = -1);
    void dispatcher(ConstBufferPtr msg);
    
    // Handler
    void requestPiece(int index = -1);
    
    // Helper
    ConstBufferPtr getBitfieldConstBufferPtr();
    BufferPtr createPeerBitfield(ConstBufferPtr peerBitfield);
    void setBit(int index, BufferPtr bitfield);
    bool hasPiece(int index, ConstBufferPtr bitfield);
    bool hasBeenRequested(int index, ConstBufferPtr bitfield);
    vector<uint8_t> pieceHashFromTorrent(int index);
    bool validPiece(int index, ConstBufferPtr fileBuffer);
    int pieceLength(int index);
    
    // I/O
    ConstBufferPtr readPieceFromFile(int index);
    void writePieceToFile(int index, const char *piece);
    
    // Processing logic
    void handshakeMsg(ConstBufferPtr msg);
    void bitfieldMsg(ConstBufferPtr msg);
    void interestedMsg(ConstBufferPtr msg);
    void unchokeMsg(ConstBufferPtr msg);
    void requestMsg(ConstBufferPtr msg);
    void pieceMsg(ConstBufferPtr msg);
    void haveMsg(ConstBufferPtr msg);
};

} // namespace sbt

#endif // SBT_CLIENT_HPP
