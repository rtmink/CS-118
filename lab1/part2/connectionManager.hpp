//
//  connectionManager.h
//  
//
//  Created by RyanT Mink on 2/14/15.
//
//

#ifndef SBT_CONNECTION_MANAGER_HPP
#define SBT_CONNECTION_MANAGER_HPP

#include "common.hpp"
#include "client.hpp"
#include "trackerHandler.hpp"
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
    
    // Threads Args - tracker
    struct TrackerConnectionThreadArgs {
        struct shared_vars *shared;
        int threadId;
    };
    
    // Threads Args - peer
    struct PeerConnectionThreadArgs {
        struct shared_vars *shared;
        PeerInfo peerInfo;
        int sockFD;
        int threadId;
    };
    
    class ConnectionManager
    {
    public:
        ConnectionManager(const std::string& port, const std::string& torrent);
        static void* trackerConnectionHandler(void* args);
        static void* peerConnectionHandler(void* args);
        
        static void* testMe(void* args);
        
    private:
        // Global Variable
        struct shared_vars *m_shared;
        
        // Other
        void createTrackerConnectionThread();
        
        // TODO: testing only
        // Helper
        void setBit(int index, BufferPtr bitfield);
        vector<uint8_t> pieceHashFromTorrent(int index);
        bool validPiece(int index, ConstBufferPtr fileBuffer);
        int pieceLength(int index);
    };
    
} // namespace sbt

#endif // SBT_CONNECTION_MANAGER_HPP