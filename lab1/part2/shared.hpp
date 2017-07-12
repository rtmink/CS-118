//
//  Shared.h
//  
//
//  Created by RyanT Mink on 2/14/15.
//
//

#ifndef SBT_SHARED_HPP
#define SBT_SHARED_HPP

#include "common.hpp"
#include "meta-info.hpp"
#include "tracker-response.hpp"
#include "util/buffer.hpp"

#include <string.h>
#include <pthread.h>
#include <queue>
#include <set>

using namespace std;

namespace sbt {
    
    struct shared_vars
    {
        // GLOBAL VARS ===
        // *** multiple threads can access this ***
        
        // MetaInfo contains:
        // - filename
        // - file length
        // - file's piece length
        // - announce
        
        
        // Read-only
        MetaInfo s_metaInfo;
        string s_listeningPort;
        int s_numPieces;
        int s_bitfieldLength;
        string s_myID;
        
        // Read/Write
        
        set<string> s_connectedPeers;
        map<int, queue<int>> s_requestedPieces;
        BufferPtr s_outstandingRequests;
        BufferPtr s_myBitfield;
        vector<PeerInfo> s_peers;
        
        int s_downloaded;
        int s_uploaded;
        int s_left;
        bool s_completed;
        
        // Pthread vars
        pthread_mutex_t t_mutex;
        int t_threadCount = 0;
        pthread_t t_threads[10];
        bool t_isUsed[10] = {0};
        const int t_MAX_THREAD = 10;
    };
    
} // namespace sbt

#endif // SBT_SHARED_HPP