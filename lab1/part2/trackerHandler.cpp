//
//  trackerHandler.cpp
//  
//
//  Created by RyanT Mink on 2/14/15.
//
//

#include "trackerHandler.hpp"

#define DEBUG 0
#define DEBUG2 0

#define BUFFER_SIZE 512
#define HTTP_VERSION "1.0"
#define MY_IP "127.0.0.1"

using namespace std;

namespace sbt {
    
    TrackerHandler::TrackerHandler(struct shared_vars *shared)
    {
        if (DEBUG2) {
            cout << "TrackerHandler constructor" <<  endl;
        }
        
        // Init state
        m_hasSentCompletedMsg = false;
        
        // Keep shared variables with other threads
        m_shared = shared;
        
        // Get url-encoded info hash
        m_urlEncodedHash = url::encode(m_shared->s_metaInfo.getHash()->get(), m_shared->s_metaInfo.getHash()->size());
        
        // Get url-encoded Peer ID
        string peerID = m_shared->s_myID;
        Buffer peerIDBuffer((void *)peerID.c_str(), peerID.size());
        m_urlEncodedPeerID = url::encode(peerIDBuffer.get(), peerIDBuffer.size());
        
        // Get IP
        m_clientIP = MY_IP;
        
        if (DEBUG) {
            cout << "Name: " << m_shared->s_metaInfo.getName() << endl;
            cout << "Len: " << m_shared->s_metaInfo.getLength() << endl;
            cout << "Piece len: " << m_shared->s_metaInfo.getPieceLength() << endl;
            cout << "Announce: " << m_shared->s_metaInfo.getAnnounce() << endl;
            cout << "Hash: " << m_urlEncodedHash << endl << endl;
        }
        
        // TODO: ensure this is robust
        // Get tracker's http protocol, hostname, port no, and url path
        string announce = m_shared->s_metaInfo.getAnnounce();
        size_t found = announce.find("://");
        
        string aa = announce.substr(found+3);
        size_t found2 = aa.find(":");
        size_t found3 = aa.find("/");
        
        m_protocol = announce.substr(0, found);
        
        if (found2 == string::npos) {
            
            m_trackerHostname = aa.substr(0, found3);
            
            // no port specified
            if (m_protocol == "https")
                m_trackerPort = "443";
            else
                m_trackerPort = "80";
        } else {
            // port specified
            m_trackerHostname = aa.substr(0, found2);
            m_trackerPort = aa.substr(found2+1, found3-found2-1);
        }
        
        m_trackerPath = aa.substr(found3+1);
        
        if (DEBUG) {
            cout << "Protocol: " << m_protocol << endl;
            cout << "Hostname: " << m_trackerHostname << endl;
            cout << "Port: " << m_trackerPort << endl;
            cout << "Params: " << m_trackerPath << endl << endl;
        }
        
        // Initiate the first request to tracker
        reportStatus(STARTED);
        m_requestInterval = m_trackerResponse.getInterval();

        // Send request to tracker at specified interval
        while (1) {
            
            // Update peers
            updatePeers();
            
            // Do nothing during the interval
            sleep(m_requestInterval);
            
            // Exit loop if tracker closes the connection
            if (!reportStatus(NONE))
                break;
            
            // Update interval
            m_requestInterval = m_trackerResponse.getInterval();
        }
        
        if (DEBUG2) {
            cout << "Tracker has closed the connection" << endl;
        }
    }
    
    // LOCK
    void TrackerHandler::updatePeers()
    {
        pthread_mutex_lock(&(m_shared->t_mutex));
        
        m_shared->s_peers = m_trackerResponse.getPeers();
        int numOfPeers = m_shared->s_peers.size();
        int deletePeerI = -1;
        
        // Print out peers' info
        for (int i = 0; i < numOfPeers; i++) {
            
            if (DEBUG) {
                cout << m_shared->s_peers[i].ip << ":" << m_shared->s_peers[i].port << endl;
            }
            
            if (m_shared->s_peers[i].port == atoi(m_shared->s_listeningPort.c_str()))
                deletePeerI = i;
        }
        
        if (deletePeerI > -1)
            // Remove ourselves from the list
            m_shared->s_peers.erase(m_shared->s_peers.begin() + deletePeerI);
        
        pthread_mutex_unlock(&(m_shared->t_mutex));
    }
    
    bool TrackerHandler::reportStatus(StatusEventEnum event)
    {
        string eventStr = "";
        
        switch (event) {
            case STARTED:
                eventStr = "started";
                m_started = true;
                
                if (DEBUG2)
                    cout << "Sending to tracker - Event: " << eventStr << endl;
                break;
                
            case STOPPED:
                eventStr = "stopped";
                m_started = false;
                break;
            
            case COMPLETED:
                eventStr = "completed";
                m_started = false;
                break;
                
            case NONE:
                eventStr = "";
                m_started = false;
                break;
        }
        
        if (DEBUG)
            cout << "Sending to tracker - Event: " << eventStr << endl;
        
        return connectToTracker();
    }
    
    bool TrackerHandler::connectToTracker()
    {
        // Build path including params
        HttpRequest req;
        req.setHost(m_trackerHostname);     // tracker's hostname
        req.setPort(stoi(m_trackerPort));   // tracker's port
        req.setMethod(HttpRequest::GET);
        req.setPath(getURLPath());          // tracker's url path
        req.setVersion(HTTP_VERSION);
        req.addHeader("Accept-Language", "en-US");
        
        Buffer requestBuffer(req.getTotalLength());
        req.formatRequest(reinterpret_cast<char *>(requestBuffer.buf()));
        
        if (DEBUG)
            cout << requestBuffer.buf() << endl;
        
        // Socket setup
        struct sockaddr_in serverAddr;
        
        // Create a socket
        if ((m_sockFD = socket(AF_INET, SOCK_STREAM, 0)) == -1)
        {
            perror("socket: can't open a socket.");
            exit(1);
        }
        
        // Get the tracker's IP from hostname
        bool connected = false;
        serverAddr.sin_family = AF_INET;
        serverAddr.sin_port = htons(atoi(m_trackerPort.c_str()));
        
        struct hostent *he = gethostbyname(m_trackerHostname.c_str());
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
            perror("connect: can't connect to tracker.");
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
        
        ssize_t sendRet;
        ssize_t recvRet;
        size_t responseBufferOffset = 0;
        char *responseBuffer = (char *)malloc(BUFFER_SIZE);
        
        // send/receive data to/from connection
        if ((sendRet = send(m_sockFD, requestBuffer.buf(), requestBuffer.size(), 0)) == -1) {
            perror("send: can't send request to tracker.");
            exit(1);
        }
        
        if (DEBUG) {
            cout << "Actually sent to tracker: " << sendRet << endl;
            cout << "Desired sent to tracker: " << requestBuffer.size() << endl;
        }
        
        // Store response in dynamically-allocated buffer
        while (1) {
            if ((recvRet = recv(m_sockFD, responseBuffer + responseBufferOffset, BUFFER_SIZE, 0)) == -1) {
                perror("recv: can't receive response from tracker.");
                exit(1);
            }
            
            if (DEBUG)
                cout << "Actually received size: " << recvRet << endl;
            
            if (recvRet == 0) {
                // The remote side has closed the connection on you
                // close current connection then
                if (DEBUG)
                    cout << "Connection ended." << endl;
                break;
            }
            
            responseBufferOffset += recvRet;
            if (recvRet == BUFFER_SIZE)
                responseBuffer = (char *)realloc(responseBuffer, responseBufferOffset + BUFFER_SIZE);
        }
        
        if (DEBUG)
            cout << responseBuffer << endl;
        
        stringstream ss;
        ss << responseBuffer;
        
        if (responseBufferOffset == 0) {
            // Tracker has closed the connection for good
            close(m_sockFD);
            return false;
        }
        
        HttpResponse resp;
        resp.parseResponse(responseBuffer, strlen(responseBuffer));
        
        // IMPORTANT
        free(responseBuffer);
        
        // findHeader works because HttpResponse is a child of HttpHeaders
        string contentLength = resp.findHeader("Content-Length");
        
        if (DEBUG) {
            cout << "Status code: " << resp.getStatusCode() << endl;
            cout << "Status message: " << resp.getStatusMsg() << endl;
            cout << "HTTP Version: " << resp.getVersion() << endl;
            cout << "HTTP header total length: " << resp.getTotalLength() << endl; // size_t
            cout << "Content-Length: " << contentLength << endl;
        }
        
        // TODO: make it more robust
        // Content-Length is the length of the HTTP Response Body
        string httpBody = ss.str().substr(ss.str().find("\r\n\r\n") + 4, atoi(contentLength.c_str()));
        
        if (DEBUG)
            cout << "HTTP body: " << httpBody << endl;
        
        ss.str("");
        ss << httpBody;
        
        if (DEBUG)
            cout << "HTTP body ss: " << ss.str() << endl;
        
        // Get tracker's response in the form of a dictionary
        bencoding::Dictionary responseDict;
        responseDict.wireDecode(ss);
        m_trackerResponse.decode(responseDict);
        
        // Close socket
        close(m_sockFD);
        
        return true;
    }
    
    // TODO: uploaded, downloaded, and left change dynamically
    // use class vars that all the threads share
    
    /*
     Example of the GET request path:
     http://tracker.com:80/announce
     ?infoHash=123
     &peer_id=asd
     &ip=127.0.0.1
     &port=6881
     &uploaded=100
     &downloaded=100
     &left=9000
     &event=stopped
     */
    
    // Params
    // ip => my IP
    // port => port supplied above
    // peer_id => randomly self-generated
    //
    // LOCK
    string TrackerHandler::getURLPath()
    {
        pthread_mutex_lock(&(m_shared->t_mutex));
        
        string path = "/" + m_trackerPath + "?info_hash=" + m_urlEncodedHash + "&peer_id=" + m_urlEncodedPeerID + "&port=" + m_shared->s_listeningPort + "&uploaded=" + to_string(m_shared->s_uploaded) + "&downloaded=" + to_string(m_shared->s_downloaded) + "&left=" + to_string(m_shared->s_left);
        
        //"&ip=" + m_clientIP
        
        if (m_started)
            path += "&event=started";
        else if (!m_hasSentCompletedMsg && m_shared->s_completed) {
            m_hasSentCompletedMsg = true;
            path += "&event=completed";
            
            if (DEBUG2)
                cout << "Sending to tracker - completed" << endl;
        }
        
        pthread_mutex_unlock(&(m_shared->t_mutex));
        
        return path;
    }
    
} // namespace sbt