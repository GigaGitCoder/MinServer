#include "MessengerServer.h"
#include <iostream>
#include <string>

using namespace std;

int main(int argc, char** argv) {
    int port = 5555;
    if (argc > 1) {
        port = atoi(argv[1]);
    }

    try {
        MessengerServer server;
        if (!server.start(port)) {
            cerr << "Failed to start server" << endl;
            return 1;
        }

        cout << "Messenger Server running on port " << port << endl;
        cout << "Press Enter to stop the server..." << endl;

        string dummy;
        getline(cin, dummy);

        server.stop();
        cout << "Server stopped." << endl;
    }
    catch (const exception& ex) {
        cerr << "Fatal error: " << ex.what() << endl;
        return 1;
    }

    return 0;
}
