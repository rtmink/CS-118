//
//  connectionManager.cpp
//  
//
//  Created by RyanT Mink on 2/14/15.
//
//

#include "connectionManager.hpp"

#define DEBUG 0
#define DEBUGX 0

#define BUFFER_SIZE 512
#define PEER_ID "SIMPLEBT.TEST.PEERID"

using namespace std;

namespace sbt {
    
    /**
     * Start Routine for Handling Tracker's Connection
     */
    void* ConnectionManager::trackerConnectionHandler(void* args)
    {
        if (DEBUG) {
            cout << ">>>Tracker Conn Thread<<<" << endl;
        }
        
        TrackerConnectionThreadArgs threadArgs = *(TrackerConnectionThreadArgs *)args;
        struct shared_vars *shared = threadArgs.shared;
        pthread_mutex_lock(&(shared->t_mutex));
        
        shared->t_threadCount++;
        
        if (DEBUG) {
            cout << "Port: " << shared->s_listeningPort << endl;
            cout << "Num of pieces: " << shared->s_numPieces << endl;
        }
        
        pthread_mutex_unlock(&(shared->t_mutex));
        
        // Connect to tracker to get peers
        TrackerHandler m_trackerHandler(shared);
        
        return 0;
    }
    
    /**
     * Start Routine for Handling Peer's Connection
     */
    void* ConnectionManager::peerConnectionHandler(void* args)
    {
        if (DEBUG) {
            cout << ">>>Peer Conn Thread<<<" << endl;
        }
        
        PeerConnectionThreadArgs threadArgs = *(PeerConnectionThreadArgs *)args;
        struct shared_vars *shared = threadArgs.shared;
        pthread_mutex_lock(&(shared->t_mutex));
        
        shared->t_threadCount++;
        
        int threadID = threadArgs.threadId;
        
        if (DEBUG) {
            cout << ">>>Peer thread id: " << threadID  << endl;
            cout << endl;
        }
        
        // Initialize requestedPieces
        queue<int> pieceIndices;
        shared->s_requestedPieces[threadID] = pieceIndices;
        
        pthread_mutex_unlock(&(shared->t_mutex));
        
        // Connect to tracker to get peers
        
        if (threadArgs.sockFD != -1) {
            // Start connection as a SERVER
            
            if (DEBUG) {
                cout << ">>>Peer as SERVER " << endl;
                cout << endl;
            }
            
            Client client(shared, threadArgs.sockFD, threadID);
        } else {
            // Start connection as a CLIENT
            
            if (DEBUG) {
                cout << ">>>Peer as CLIENT " << endl;
                cout << endl;
            }
            
            Client client(shared, threadArgs.peerInfo, threadID);
        }
        
        return 0;
    }
    
    // TEST only
    void* ConnectionManager::testMe(void* args)
    {
        cout << "Whats up man?" << endl;
        return 0;
    }
    
    ConnectionManager::ConnectionManager(const std::string& port, const std::string& torrent)
    {
        if (DEBUG) {
            cout << "Connection Manager Constructor..." << endl;
        }
        
        struct shared_vars shared;
        m_shared = &shared;
        
        m_shared->s_myID = PEER_ID;
        m_shared->s_listeningPort = port;
        
        // Read from the given torrent file
        ifstream torrentStream(torrent.c_str());
        if (!torrentStream) {
            perror("Can't open torrent file.");
            exit(1);
        }
        
        // Create metaInfo
        MetaInfo mi;
        mi.wireDecode(torrentStream);
        m_shared->s_metaInfo = mi;
        
        // Get number of pieces from torrent file (rounding up)
        m_shared->s_numPieces = (m_shared->s_metaInfo.getLength() + m_shared->s_metaInfo.getPieceLength() - 1) / m_shared->s_metaInfo.getPieceLength();
        
        if (DEBUG) {
            cout << "Num of pieces: " << m_shared->s_numPieces << endl;
            cout << "getPieces size:" << m_shared->s_metaInfo.getPieces().size() << endl;
        }
        
        // Initialize bitfield and outstandingRequests to 0s
        m_shared->s_bitfieldLength = (m_shared->s_numPieces + 8 - 1) / 8;
        auto bitfieldBuffer = make_shared<Buffer>();
        
        for (int k = 0; k < m_shared->s_bitfieldLength; k++)
            bitfieldBuffer->push_back(0x00);
        
        m_shared->s_myBitfield = bitfieldBuffer;
        m_shared->s_outstandingRequests = bitfieldBuffer;
        
        // Check if the file exists in current working directory
        // Create / open file
        fstream fs;
        fs.open(m_shared->s_metaInfo.getName().c_str());
        
        if (!fs)
        {
            // File does not exist
            cout << "File does not exist dude!" << endl;
            
            fs.close();
            fs.open(m_shared->s_metaInfo.getName().c_str(), fstream::out);
            fs.close();
            
            //fs.open(m_shared->s_metaInfo.getName().c_str());
            //fs.write();
            
            m_shared->s_left = m_shared->s_metaInfo.getLength();
        }
        else
        {
            // File exists
            cout << "File exists dude!" << endl;
            
            uint32_t pieceLen;
            
            // Check the hash of each piece and set the bit in bitfield
            for (int i = 0; i < m_shared->s_numPieces; i++) {
                
                pieceLen = pieceLength(i);
                
                // File buffer
                char *fileBuffer = new char[pieceLen]();
                
                fs.seekg(i * m_shared->s_metaInfo.getPieceLength());
                fs.read(fileBuffer, pieceLen);
                
                fileBuffer[pieceLen] = '\0';
                
                //cout << "***Piece " << i << ": " << endl << fileBuffer << endl << endl;
                
                cout << "Piece len: " << pieceLen << endl;
                cout << "Buf size: " << strlen(fileBuffer) << endl;
                
                // Set the corresponding bit appropriately
                auto fileBufferPtr = make_shared<Buffer>(fileBuffer, pieceLen);
                
                if (validPiece(i, fileBufferPtr)) {
                    cout << "Hash strs for piece " << i << " are equal!" << endl;
                    setBit(i, m_shared->s_myBitfield);
                }
                
                delete[] fileBuffer;
            }
            
            m_shared->s_left = 0;
        }
        
        // Init states
        m_shared->s_downloaded = 0;
        m_shared->s_uploaded = 0;
        
        m_shared->s_completed = false;
        
        
        /**
         * Bind and Listen to specified port
         *
         */
        
        int maxSockFD = 0;
        
        fd_set readFDs;
        fd_set tmpFDs;
        FD_ZERO(&readFDs);
        FD_ZERO(&tmpFDs);
        
        // create a socket using TCP IP
        int sockfd = socket(AF_INET, SOCK_STREAM, 0);
        maxSockFD = sockfd;
        
        // put the socket in the socket set
        FD_SET(sockfd, &tmpFDs);
        
        // allow others to reuse the address
        int yes = 1;
        if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) == -1) {
            perror("setsockopt");
            exit(1);
        }
        
        // bind address to socket
        struct sockaddr_in addr;
        addr.sin_family = AF_INET;
        addr.sin_port = htons(atoi(port.c_str()));     // short, network byte order
        addr.sin_addr.s_addr = inet_addr("127.0.0.1");
        memset(addr.sin_zero, '\0', sizeof(addr.sin_zero));
        if (bind(sockfd, (struct sockaddr*)&addr, sizeof(addr)) == -1) {
            perror("bind");
            exit(1);
        }
        
        if (DEBUG) {
            cout << "Binding to PORT: " << port << endl;
        }
        
        // set the socket in listen status
        if (listen(sockfd, 10) == -1) {
            perror("listen");
            exit(1);
        }
        
        /**
         * Spawn a thread for tracker's connection
         */
        //createTrackerConnectionThread();
        
        TrackerConnectionThreadArgs arg;
        
        pthread_mutex_lock(&(m_shared->t_mutex));
        
        if (m_shared->t_threadCount >= m_shared->t_MAX_THREAD) {
            
            if (DEBUG) {
                cout << "Threads not available..." << endl;
            }
            
            // No threads available atm
            //sleep(1); // TODO: be careful here
            //continue;
        }
        else {
            
            if (DEBUG) {
                cout << "Threads available..." << endl;
            }
            
            // Threads available
            for (int i = 0; i < m_shared->t_MAX_THREAD; i++) {
                
                if (m_shared->t_isUsed[i] == false) {
                    
                    if (DEBUG) {
                        cout << "Assigning thread id: " << i << endl;
                    }
                    
                    arg.threadId = i;
                    arg.shared = m_shared;
                    m_shared->t_isUsed[i] = true;
                    break;
                }
                
            }
        }
        
        pthread_mutex_unlock(&(m_shared->t_mutex));
        
        int ret = pthread_create(&(m_shared->t_threads[arg.threadId]), 0, trackerConnectionHandler, (void *)&arg);
        
        pthread_mutex_lock(&(m_shared->t_mutex));
        if (ret != 0) {
            cout << "Error in creating thread: " << ret << endl;
        } else {
            cout << "No error!!!" << endl;
        }
        
        cout << "Done creating thread" << endl;
        pthread_mutex_unlock(&(m_shared->t_mutex));
        
        // initialize timer
        struct timeval tv;
        tv.tv_sec = 1;
        tv.tv_usec = 0;
        
        if (DEBUG) {
            cout << "About to loop..." << endl;
        }
        
        while(1) {
            readFDs = tmpFDs;
            
            // set up watcher
            if (select(maxSockFD + 1, &readFDs, NULL, NULL, &tv) == -1) {
                perror("select");
                exit(1);
            }
            
            if (FD_ISSET(sockfd, &readFDs)) {
                // There is incoming connection
                
                if (DEBUG) {
                    cout << "******Incoming request******" << endl;
                }
                
                // TODO: sleep after creating tracker
                sleep(2);
                
                struct sockaddr_in clientAddr;
                socklen_t clientAddrSize;
                int clientSockFD = accept(sockfd, (struct sockaddr*)&clientAddr, &clientAddrSize);
                
                if (clientSockFD == -1) {
                    perror("accept");
                    exit(1);
                }
                
                char ipstr[INET_ADDRSTRLEN] = {'\0'};
                inet_ntop(clientAddr.sin_family, &clientAddr.sin_addr, ipstr, sizeof(ipstr));
                
                if (DEBUG) {
                    std::cout << "Accept a connection from: " << ipstr << ":" << ntohs(clientAddr.sin_port) << std::endl;
                }
                
                
                // <
                
                PeerConnectionThreadArgs arg3;
                
                pthread_mutex_lock(&(m_shared->t_mutex));
                
                if (m_shared->t_threadCount >= m_shared->t_MAX_THREAD) {
                    
                    if (DEBUG) {
                        cout << "Threads not available..." << endl;
                    }
                    
                    // No threads available atm
                    //sleep(1); // TODO: be careful here
                    //continue;
                }
                else {
                    
                    if (DEBUG) {
                        cout << "Threads available..." << endl;
                    }
                    
                    // Threads available
                    for (int i = 0; i < m_shared->t_MAX_THREAD; i++) {
                        
                        if (m_shared->t_isUsed[i] == false) {
                            
                            if (DEBUG) {
                                cout << "Assigning thread id: " << i << endl;
                            }
                            
                            arg3.threadId = i;
                            arg3.shared = m_shared;
                            arg3.sockFD = clientSockFD;
                            m_shared->t_isUsed[i] = true;
                            break;
                        }
                        
                    }
                }
                
                pthread_mutex_unlock(&(m_shared->t_mutex));
                
                int theRes = pthread_create(&(m_shared->t_threads[arg3.threadId]), 0, peerConnectionHandler, (void *)&arg3);
                
                if (theRes != 0) {
                    if (DEBUG)
                        cout << "Error in creating listening thread: error: " << theRes << endl;
                }
                
                // TODO: sleep after spawning server thread
                sleep(1);
                
                // >
                
            }
            else {
                // There is no incoming connection
                
                //sleep(1);
                usleep(1100000);
                
                if (DEBUG) {
                    //cout << "******NO Incoming request******" << endl;
                }
                
                // TODO: there must be a way for tracker to tell us that they have received peer list
                
                
                // Peer(s)
                // <
                
                // TODO: testing only
                // Create thread handling downloads
                
                vector<PeerConnectionThreadArgs> peerThreadsArgs;
                PeerConnectionThreadArgs arg2;
                
                pthread_mutex_lock(&(m_shared->t_mutex));
                
                for (int i = 0; i < (int)m_shared->s_peers.size(); i++) {
                    
                    string peerID = m_shared->s_peers[i].peerId;
                    
                    if (m_shared->s_connectedPeers.find(peerID) != m_shared->s_connectedPeers.end()) {
                        // We already have connection with peer
                        continue;
                    }
                    
                    // Add peer to connected list
                    m_shared->s_connectedPeers.insert(peerID);
                    
                    if (DEBUG) {
                        cout << endl << "Peer with ID: " << peerID << endl;
                    }
                    
                    if (m_shared->s_peers[i].peerId != m_shared->s_myID) {
                        
                        if (m_shared->t_threadCount >= m_shared->t_MAX_THREAD) {
                            
                            if (DEBUG) {
                                cout << "Threads not available..." << endl;
                            }
                            
                            // No threads available atm
                            //sleep(1); // TODO: be careful here
                            //continue;
                        }
                        else {
                            
                            if (DEBUG) {
                                cout << "Threads available..." << endl;
                            }
                            
                            // Threads available
                            for (int j = 0; j < m_shared->t_MAX_THREAD; j++) {
                                
                                if (m_shared->t_isUsed[j] == false) {
                                    
                                    if (DEBUG) {
                                        cout << "Assigning thread id: " << j << endl;
                                        cout << "For peer id: " << m_shared->s_peers[i].peerId << endl << endl;
                                    }
                                    PeerConnectionThreadArgs arg2;
                                    
                                    arg2.threadId = j;
                                    arg2.shared = m_shared;
                                    arg2.peerInfo = m_shared->s_peers[i];
                                    arg2.sockFD = -1;
                                    m_shared->t_isUsed[j] = true;
                                    
                                    peerThreadsArgs.push_back(arg2);
                                    break;
                                }
                                
                            } // for
                        } // else
                        
                    }
                    
                } // for
                
                pthread_mutex_unlock(&(m_shared->t_mutex));
                
                // Now spawn the threads
                int retVal = 0;
                for (int i = 0; i < (int)peerThreadsArgs.size(); i++) {
                    PeerConnectionThreadArgs dArg = peerThreadsArgs[i];
                    
                    if (DEBUG) {
                        cout << "Creating thread for peer ID: " << dArg.peerInfo.peerId << endl;
                        cout << "Creating thread for thread ID: " << dArg.threadId << endl;
                        cout << endl;
                    }
                    
                    retVal = pthread_create(&(m_shared->t_threads[dArg.threadId]), 0, peerConnectionHandler, (void *)&dArg);
                    
                    // TODO: test only
                    sleep(1);
                    //usleep(100000);
                    
                    if (retVal != 0) {
                        cout << "Error in creating thread - error id: " << retVal << endl;
                    }
                }
                
                // >
                
            }
        }
        
        
        if (DEBUG) {
            cout << "<<<>>>WAITING ON ALL THREADS<<<>>>" << endl;
        }
        
        // Wait on all threads
        while (m_shared->t_threadCount > 0) {
            sleep(1);
        }
        
        // ==================================
    }
    
    
    /**
     * Helper functions
     */
    
    void ConnectionManager::createTrackerConnectionThread()
    {
        
    }
    
    void ConnectionManager::setBit(int index, BufferPtr bitfield)
    {
        if (index >= (int)(bitfield->size() * 8))
            // Invalid index
            return;
        
        int modIndex = index % 8;
        bitfield->at(index / 8) |= 0x01 << (8 - modIndex - 1);
    }
    
    vector<uint8_t> ConnectionManager::pieceHashFromTorrent(int index)
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
    
    bool ConnectionManager::validPiece(int index, ConstBufferPtr fileBuffer)
    {
        ConstBufferPtr sha1 = util::sha1(fileBuffer);
        vector<uint8_t> tv = pieceHashFromTorrent(index);
        
        // Check if the two bitfield vectors are equal
        return equal(tv.begin(), tv.begin() + 20, sha1->begin());
    }
    
    int ConnectionManager::pieceLength(int index)
    {
        return index == (m_shared->s_numPieces - 1)
        ? m_shared->s_metaInfo.getLength() - (m_shared->s_metaInfo.getPieceLength() * (m_shared->s_numPieces - 1))
        : m_shared->s_metaInfo.getPieceLength();
    }
    
} // namespace sbt