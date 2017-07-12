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

#include "client.hpp"

#define DEBUG 0
#define DEBUGX 0
#define DEBUGY 0

#define BUFFER_SIZE 3000
#define SHA1_LEN 20
#define MSG_ID_OFFSET 4
#define MY_HANDSHAKE_LENGTH 68

using namespace std;

namespace sbt {

    // Constructor for connection that starts as a client - downloading
    Client::Client(struct shared_vars *shared, PeerInfo peerInfo, int threadID)
    {
        if (DEBUG) {
            cout << "^^^Starting client connection handler for peer: " << peerInfo.peerId << endl;
        }
        
        m_isClient = true;
        m_shared = shared;
        m_threadID = threadID;
        
        initStates();
        
        m_peerInfo = peerInfo;
        
        // Create a socket
        setupConnection();
        
        // Send the first request - HANDSHAKE msg to peer
        handshakeMessenger();
        
        // Wait for incoming requests
        recvMsg();
        
        // We are done downloading all the pieces
        // set the event to "completed"
        // We are done downloading this piece
        // Check if we set the bitfield correctly
        
        if (DEBUG) {
            cout << endl << "Checking if we set the bitfield correctly!!!" << endl;
            for (int i = 0; i < m_shared->s_numPieces; i++) {
                if (hasPiece(i, getBitfieldConstBufferPtr()))
                    cout << "We have piece: " << i << endl;
                else
                    cout << "We don't have piece: " << i << endl;
            }
            cout << endl;
        }
    }

    // Constructor for connection that starts as a server - uploading
    Client::Client(struct shared_vars *shared, int sockFD, int threadID)
    {
        m_isClient = false;
        m_shared = shared;
        m_threadID = threadID;
        
        initStates();
        
        m_sockFD = sockFD;
        
        // Create a socket
        //setupConnection();
        
        // Receive peer's handshake msg
        //dispatcher(msg);
        
        // Wait for incoming requests
        recvMsg();
    }
        
    void Client::initStates()
    {
        // Initialize connection states
        m_isHandshakeReceived = false;  // peer's handshake msg
        m_hasHandshaked = false;
        m_hasBitfield = false;
        m_amInterested = false;
        m_amChoking = true;
        m_peerInterested = false;
        m_peerChoking = true;
    }
        
    void Client::handshakeMsg(ConstBufferPtr msg)
    {
        // Check peer's Handshake response
        
        if (msg->size() != MY_HANDSHAKE_LENGTH) {
            // error: Not a handshake msg
            cout << "Wrong Handshake Msg Length" << endl;
            exit(0);
        }
        
        msg::HandShake peerHandshake;
        peerHandshake.decode(msg);
        ConstBufferPtr peerInfoHash = peerHandshake.getInfoHash();
        string peerID = peerHandshake.getPeerId();
        
        if (DEBUG) {
            cout << "Peer's Handshake's PeerID: " << peerID << endl;
        }
        
        // TODO: check infoHash
        
        if (m_isClient) {
            // We start as a client - Downloading
            // TODO: Check if the peer(ID) is valid
            
            m_isHandshakeReceived = true;
            m_hasHandshaked = true;
            
            // Send BITFIELD msg
            messenger(msg::MSG_ID_BITFIELD);
            
        } else {
            // We start as a server - Uploading
            // Send our handshake msg as a response to the peer's handshake msg
            
            pthread_mutex_lock(&(m_shared->t_mutex));
            
            for (int i = 0; i < (int)m_shared->s_peers.size(); i++) {
                
                if (m_shared->s_peers[i].peerId == peerID) {
                    // Peer is on the list
                    
                    if (DEBUG)
                        cout << "Peer is on the list !!!!" << endl;
                    
                    // Save Peer's INFO
                    m_peerInfo = m_shared->s_peers[i];
                    break;
                }
            }
            
            pthread_mutex_unlock(&(m_shared->t_mutex));
            
            m_isHandshakeReceived = true;
            
            // Send HANDSHAKE msg
            handshakeMessenger();
            
            m_hasHandshaked = true; // TODO: here?
        }
    }

    void Client::bitfieldMsg(ConstBufferPtr msg)
    {
        m_hasBitfield = true;
        
        msg::Bitfield peerBF;
        peerBF.decode(msg);
        m_peerBitfield = createPeerBitfield(peerBF.getBitfield());
        
        if (m_isClient) {
            // We start as a client - downloading
            // TODO: Need to check peer's bitfield for valid pieces we want
            
            // Send INTERESTED msg
            m_amInterested = true;
            messenger(msg::MSG_ID_INTERESTED);
            
        } else {
            // We start as a server - uploading
            // TODO: Only need to check if peer's bitfield's length is equal to ours
            
            // Send BITFIELD msg
            messenger(msg::MSG_ID_BITFIELD);
        }
    }

    void Client::interestedMsg(ConstBufferPtr msg)
    {
        // Peer is interested in our pieces
        if (!m_hasBitfield) {
            // error: Should have peer's bitfield
            cout << "Must have peer's bitfield" << endl;
            exit(0);
        }
        
        m_peerInterested = true;
        
        // Send UNCHOKE msg
        m_amChoking = false; // TODO: here?
        messenger(msg::MSG_ID_UNCHOKE);
    }

    void Client::unchokeMsg(ConstBufferPtr msg)
    {
        // Peer has allowed us to download from them
        if (!m_hasBitfield) {
            // error: Should have peer's bitfield
            cout << "Must have peer's bitfield" << endl;
            exit(0);
        }
        
        m_peerChoking = false;
        
        // Send REQUEST msg
        requestPiece();
    }

    void Client::requestMsg(ConstBufferPtr msg)
    {
        // Peer wants to download a piece from us
        msg::Request request;
        request.decode(msg);
        
        int index = request.getIndex();
        int begin = request.getBegin();
        //int length = request.getLength(); // TODO: need this?
        
        // Check if we actually have the piece
        if (hasPiece(index, getBitfieldConstBufferPtr())) {
            
            if (DEBUG) {
                cout << "Send the requested piece " << index << endl;
            }
            
            // Send PIECE msg
            messenger(msg::MSG_ID_PIECE, index, begin);
        }
        else {
            // We do not have the piece
            if (DEBUG) {
                cout << "We do not have the requested piece " << index << endl;
            }
            exit(0);
        }
    }

    void Client::pieceMsg(ConstBufferPtr msg)
    {
        // Peer uploads the piece to us
        msg::Piece piece;
        piece.decode(msg);
        
        if (DEBUG) {
            //cout << "Peer's Piece MSG ID: " << (int)piece.getId() << endl;
            cout << "Receive PIECE from peer: " << m_peerInfo.peerId << endl;
        }
        
        uint32_t begin = piece.getBegin();
        uint32_t index = piece.getIndex();
        ConstBufferPtr block = piece.getBlock();
        
        if (DEBUGY) {
            cout << "Peer's Piece index: " << index << endl;
            cout << "Peer's Piece begin: " << begin << endl;
            cout << "Peer's Piece block size: " << block->size() << endl;
            //cout << "Peer's Piece: " << block->get() << endl;
        }
        
        const char *blockBuf = reinterpret_cast<const char*>(block->get());
        
        if (validPiece(index, block)) {
            
            // Valid piece
            
            if (DEBUG) {
                cout << "Peer has the valid piece" << endl;
                cout << "Writing piece to file..." << endl;
            }
            
            writePieceToFile(index, blockBuf);
            
            // Set the bitfield for the corresponding piece
            setBit(index, m_shared->s_myBitfield);
            
            // Update "downloaded", "left", & "completed" info for tracker
            // LOCK
            pthread_mutex_lock(&(m_shared->t_mutex));
            
            m_shared->s_downloaded += block->size();
            m_shared->s_left -= block->size();
            
            if (m_shared->s_left == 0)
                m_shared->s_completed = true;
            
            
            m_shared->s_requestedPieces[m_threadID].push(index);
            
            // Update requested pieces
            int rpSize = m_shared->s_requestedPieces.size();
            
            for (int i = 1; i <= rpSize; i++) {
                
                if (i == m_threadID)
                    continue;
                
                // Send HAVE messages from other threads
                while (!m_shared->s_requestedPieces[i].empty()) {
                    int curIndex = m_shared->s_requestedPieces[i].front();
                    m_shared->s_requestedPieces[i].pop();
                    
                    msg::Have have(curIndex);
                    ConstBufferPtr haveMsg = have.encode();
                    
                    // Send HAVE msg
                    messenger(msg::MSG_ID_HAVE, curIndex);
                }
            }
            
            pthread_mutex_unlock(&(m_shared->t_mutex));
            
            // Send HAVE msgs to all peers
            msg::Have have(index);
            ConstBufferPtr haveMsg = have.encode();
            
            if (DEBUG) {
                cout << "Sending HAVE msg for piece " << index << endl;
            }
        
            // Send HAVE msg
            messenger(msg::MSG_ID_HAVE, index);
            
            // Check if we need to send another REQUEST msg
            requestPiece();
        }
        else {
            
            // Piece not valid
            if (DEBUG) {
                cout << "Piece not valid" << endl;
                cout << "Resend Request msg" << endl;
            }
            
            // Resend REQUEST msg for the same piece
            requestPiece(m_currentPieceIndex);
        }
    }

    void Client::haveMsg(ConstBufferPtr msg)
    {
        msg::Have have;
        int index = have.getIndex();
        
        // Update peer's bitfield
        setBit(index, m_peerBitfield);
        
        // TODO:
        // if peer is the one that requests a piece from us,
        // update "uploaded"
        
        if (DEBUG) {
            cout << "Receive HAVE msg for piece: " << index << endl;
        }
        
        // LOCK
        pthread_mutex_lock(&(m_shared->t_mutex));
        m_shared->s_uploaded += pieceLength(index);
        pthread_mutex_unlock(&(m_shared->t_mutex));
    }

    void Client::requestPiece(int index)
    {
        if (index > -1) {
            // Valid index
            messenger(msg::MSG_ID_REQUEST, index, 0);
        }
        else {
            // Invalid index, search for piece to download if any
            for (int i = 0; i < m_shared->s_numPieces; i++) {
                
                if (!hasPiece(i, getBitfieldConstBufferPtr())
                    && hasPiece(i, m_peerBitfield)
                    && !hasBeenRequested(i, m_shared->s_outstandingRequests)) {
                    // We do not have the piece
                    // Peer has the piece
                    // So, request it
                    setBit(i, m_shared->s_outstandingRequests);
                    m_currentPieceIndex = i;
                    messenger(msg::MSG_ID_REQUEST, i, 0);
                    break;
                }
            }
        }
    }

    // ============================================
        
    /**
     * Helper functions
     */
    
    BufferPtr Client::createPeerBitfield(ConstBufferPtr peerBitfield)
    {
        return make_shared<Buffer>(peerBitfield->buf(), peerBitfield->size());
    }
    
    ConstBufferPtr Client::getBitfieldConstBufferPtr()
    {
        return m_shared->s_myBitfield;
    }
    
    // LOCK
    void Client::setBit(int index, BufferPtr bitfield)
    {
        pthread_mutex_lock(&(m_shared->t_mutex));
        
        if (index >= (int)(bitfield->size() * 8)) {
            // Invalid index
            pthread_mutex_unlock(&(m_shared->t_mutex));
            return;
        }
        
        int modIndex = index % 8;
        bitfield->at(index / 8) |= 0x01 << (8 - modIndex - 1);
        
        pthread_mutex_unlock(&(m_shared->t_mutex));
    }

    // LOCK
    bool Client::hasPiece(int index, ConstBufferPtr bitfield)
    {
        pthread_mutex_lock(&(m_shared->t_mutex));
        
        if (index >= (int)(bitfield->size() * 8)) {
            // Invalid index
            pthread_mutex_unlock(&(m_shared->t_mutex));
            return false;
        }
        
        if (DEBUGX) {
            cout << "Printing out given bitfield: ";
            for (int i = 0; i < (int)bitfield->size(); i++) {
                cout << (int)bitfield->at(i) << ", ";
            }
            cout << endl;
        }
        
        uint8_t curByte = bitfield->at(index / 8);
        int modIndex = index % 8;
        
        pthread_mutex_unlock(&(m_shared->t_mutex));
        
        return (curByte & (0x01 << (8 - modIndex - 1))) != 0;
    }
    
    // LOCK
    bool Client::hasBeenRequested(int index, ConstBufferPtr bitfield)
    {
        return hasPiece(index, bitfield);
    }

    vector<uint8_t> Client::pieceHashFromTorrent(int index)
    {
        // Assemble the 20 bytes for the piece
        // and compare them to the sha1 hash of the piece from the file
        int beginPieceHash = index * 20;
        int endPieceHash = beginPieceHash + 20;
        vector<uint8_t> tv;
        
        for (int j = beginPieceHash; j < endPieceHash; j++)
            tv.push_back(m_shared->s_metaInfo.getPieces()[j]);
        
        return tv;
    }
    
    bool Client::validPiece(int index, ConstBufferPtr fileBuffer)
    {
        ConstBufferPtr sha1 = util::sha1(fileBuffer);
        vector<uint8_t> tv = pieceHashFromTorrent(index);
        
        // Check if the two bitfield vectors are equal
        return equal(tv.begin(), tv.begin() + 20, sha1->begin());
    }
        
    int Client::pieceLength(int index)
    {
        return index == (m_shared->s_numPieces - 1)
                ? m_shared->s_metaInfo.getLength() - (m_shared->s_metaInfo.getPieceLength() * (m_shared->s_numPieces - 1))
                : m_shared->s_metaInfo.getPieceLength();
    }
    
    // LOCK?
    ConstBufferPtr Client::readPieceFromFile(int index)
    {
        pthread_mutex_lock(&(m_shared->t_mutex));
        
        fstream fs;
        fs.open(m_shared->s_metaInfo.getName().c_str());
        
        int pieceLen = pieceLength(index);
        char *fileBuffer = new char[pieceLen]();
        
        fs.seekg(index * m_shared->s_metaInfo.getPieceLength());
        fs.read(fileBuffer, pieceLen);
        fs.close();
        
        fileBuffer[pieceLen] = '\0';
        
        cout << "Piece len: " << pieceLen << endl;
        cout << "Buf size: " << strlen(fileBuffer) << endl;
        
        // Set the corresponding bit appropriately
        auto fileBufferPtr = make_shared<Buffer>(fileBuffer, pieceLen);
        delete[] fileBuffer;
        
        pthread_mutex_unlock(&(m_shared->t_mutex));
        
        return fileBufferPtr;
    }
    
    // LOCK?
    void Client::writePieceToFile(int index, const char *piece)
    {
        pthread_mutex_lock(&(m_shared->t_mutex));
        
        fstream fs;
        fs.open(m_shared->s_metaInfo.getName().c_str());
        fs.seekp(index * m_shared->s_metaInfo.getPieceLength());
        fs.write(piece, pieceLength(index));
        fs.close();
        
        pthread_mutex_unlock(&(m_shared->t_mutex));
    }
        
    // ============================================
        
    // TODO: HANDSHAKE msg is an exception - use id 999
    void Client::handshakeMessenger()
    {
        // HANDSHAKE
        msg::HandShake handshake(m_shared->s_metaInfo.getHash(), m_shared->s_myID);
        ConstBufferPtr msg = handshake.encode();
        
        if (DEBUG) {
            cout << "My Handshake msg: " << msg->get() << endl << endl;
        }
        
        sendMsg((void *)msg->buf(), msg->size());
    }

    void Client::messenger(uint8_t msgID, int pieceIndex, int pieceBegin)
    {
        ConstBufferPtr msg;
        
        switch (msgID) {
            case msg::MSG_ID_UNCHOKE:
            {
                msg::Unchoke unchoke;
                msg = unchoke.encode();
            }
                break;
                
            case msg::MSG_ID_INTERESTED:
            {
                msg::Interested interested;
                msg = interested.encode();
            }
                break;
                
            case msg::MSG_ID_HAVE:
            {
                msg::Have have(pieceIndex);
                msg = have.encode();
            }
                break;
                
            case msg::MSG_ID_BITFIELD:
            {
                msg::Bitfield bitfield(getBitfieldConstBufferPtr());
                msg = bitfield.encode();
            }
                break;
                
            case msg::MSG_ID_REQUEST:
            {
                msg::Request request(pieceIndex, pieceBegin, pieceLength(pieceIndex));
                msg = request.encode();
            }
                break;
                
            case msg::MSG_ID_PIECE:
            {
                msg::Piece piece(pieceIndex, pieceBegin, readPieceFromFile(pieceIndex));
                msg = piece.encode();
            }
                break;
                
            default:
                return;
        }
            
        sendMsg((void *)msg->buf(), msg->size());
    }
        
    void Client::dispatcher(ConstBufferPtr msg)
    {
        if (!m_isHandshakeReceived) {
            // We are expecting a HANDSHAKE msg
            handshakeMsg(msg);
        } else {
            // We are not expecting a HANDSHAKE msg
            
            if (!m_hasHandshaked) {
                // error: must handshake first
                cout << "Must handshake first" << endl;
                closeConnection();
                exit(0);
            }
            
            switch (msg->at(MSG_ID_OFFSET)) {
                case msg::MSG_ID_UNCHOKE:
                    unchokeMsg(msg);
                    break;
                    
                case msg::MSG_ID_INTERESTED:
                    interestedMsg(msg);
                    break;
                    
                case msg::MSG_ID_HAVE:
                    haveMsg(msg);
                    break;
                    
                case msg::MSG_ID_BITFIELD:
                    bitfieldMsg(msg);
                    break;
                    
                    
                case msg::MSG_ID_REQUEST:
                    requestMsg(msg);
                    break;
                    
                case msg::MSG_ID_PIECE:
                    pieceMsg(msg);
                    break;
            }
        }
    }

    /**
     * Socket Functions
     */
        
    void Client::sendMsg(void *requestBuffer, size_t requestBufferLength)
    {
        ssize_t sendRet;
        
        // Send/receive data to/from connection
        if ((sendRet = send(m_sockFD, requestBuffer, requestBufferLength, 0)) == -1) {
            perror("send: can't send request to peer");
            exit(1);
        }
        
        if (DEBUGY) {
            cout << "Desired sent size: " << requestBufferLength << endl;
            cout << "Actually sent size: " << sendRet << endl;
        }
    }
        
    void Client::recvMsg()
    {
        ssize_t recvRet;
        size_t responseBufferOffset = 0;
        char *responseBuffer = (char *)malloc(BUFFER_SIZE);
        memset(responseBuffer, '\0', BUFFER_SIZE);
        
        // Keep waiting for incoming requests
        while (1) {
            // Store response in dynamically-allocated buffer
            if ((recvRet = recv(m_sockFD, responseBuffer + responseBufferOffset, BUFFER_SIZE, 0)) == -1) {
                perror("recv: can't receive response from peer");
                exit(1);
            }
            
            if (DEBUGY)
                cout << "Actually received size: " << recvRet << endl;
            
            if (recvRet == 0) {
                // The remote side has closed the connection on you
                // close current connection then
                if (DEBUG)
                    cout << "Connection ended." << endl;
            }
            
            responseBufferOffset += recvRet;
            if (recvRet == BUFFER_SIZE)
                responseBuffer = (char *)realloc(responseBuffer, responseBufferOffset + BUFFER_SIZE);
            
            if (DEBUG)
                cout << responseBuffer << endl;
            
            // TODO: for now, we just assume that
            // we only need one recv to get all the messages
            auto bbuffer = make_shared<Buffer>(responseBuffer, recvRet);
            free(responseBuffer);
            
            // Dispatch msg
            dispatcher(bbuffer);
            
            // Reset vars
            responseBufferOffset = 0;
            responseBuffer = (char *)malloc(BUFFER_SIZE);
            memset(responseBuffer, '\0', BUFFER_SIZE);
        }
    }

    // We only call this when we start as a client - downloading
    void Client::setupConnection()
    {
        // Socket setup
        struct sockaddr_in serverAddr;
        
        // Create a socket
        if ((m_sockFD = socket(AF_INET, SOCK_STREAM, 0)) == -1)
        {
            perror("socket: can't open a socket.");
            exit(1);
        }
        
        // TODO: Get the tracker's IP from hostname
        bool connected = false;
        serverAddr.sin_family = AF_INET;
        serverAddr.sin_port = htons(m_peerInfo.port);
        
        struct hostent *he = gethostbyname(m_peerInfo.ip.c_str());
        for (int i = 0; he->h_addr_list[i] != NULL; i++) {
            // Connect to the first available host
            memcpy(&serverAddr.sin_addr, he->h_addr_list[i], he->h_length);
            
            if (connect(m_sockFD, (struct sockaddr *)&serverAddr, sizeof(serverAddr)) == 0) {
                // We are connected
                connected = true;
                break;
            }
        }
        
        if (!connected) {
            perror("connect: can't connect to peer.");
            exit(1);
        }
        
        struct sockaddr_in clientAddr;
        socklen_t clientAddrLen = sizeof(clientAddr);
        if (getsockname(m_sockFD, (struct sockaddr *)&clientAddr, &clientAddrLen) == -1) {
            perror("getsockname: can't get client's address.");
            exit(1);
        }
        
        char ipstr[INET_ADDRSTRLEN] = {'\0'};
        inet_ntop(clientAddr.sin_family, &clientAddr.sin_addr, ipstr, sizeof(ipstr));
        
        if (DEBUG)
            cout << "Set up a connection from: "
            << ipstr << ":" << ntohs(clientAddr.sin_port)
            << endl;
    }
    
    void Client::closeConnection()
    {
        close(m_sockFD);
    }

} // namespace sbt
