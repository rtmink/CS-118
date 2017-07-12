//
//  trackerHandler.hpp
//  
//
//  Created by RyanT Mink on 2/14/15.
//
//

#ifndef SBT_TRACKER_HANDLER_HPP
#define SBT_TRACKER_HANDLER_HPP

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

#include <sys/wait.h>
#include <netdb.h>

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

using namespace std;

namespace sbt {

    class TrackerHandler
    {
    public:
        // Need to be declared before used in argument declarations
        enum StatusEventEnum
        {
            STARTED,
            STOPPED,
            COMPLETED,
            NONE
        };
        
        TrackerHandler(struct shared_vars *shared);
        bool reportStatus(StatusEventEnum event);
        
    private:
        // Share between threads
        struct shared_vars *m_shared;
        
        // Tracker's info
        string m_protocol;
        string m_trackerHostname;
        string m_trackerPort;
        string m_trackerPath;
        
        string m_clientIP;
        string m_urlEncodedHash;
        string m_urlEncodedPeerID;
        
        // Misc
        bool m_started;
        bool m_hasSentCompletedMsg;
        int m_sockFD;
        TrackerResponse m_trackerResponse;
        uint64_t m_requestInterval;
        
        string getURLPath();
        
        bool connectToTracker();
        
        void updatePeers();
    };

} // namespace sbt


#endif // SBT_TRACKER_HANDLER_HPP