var net = require('net');
var fs = require('fs');
var sys = require('sys');
var crypto = require('crypto');
var StompFrame = require('./frame').StompFrame;
var StompFrameEmitter = require('./parser').StompFrameEmitter;

/*
Use like this:

var privateKey = fs.readFileSync('CA/newkeyopen.pem', 'ascii');
var certificate = fs.readFileSync('CA/newcert.pem', 'ascii');
var certificateAuthority = fs.readFileSync('CA/demoCA/private/cakey.pem', 'ascii');
var credentials = crypto.createCredentials({
    key: privateKey,
    cert: certificate,
    ca: certificateAuthority,
});

new SecureStompServer(8124, credentials).listen();
new StompServer(8125).listen();
*/

var StompClientCommands = [
    'CONNECT',
    'SEND',
    'SUBSCRIBE',
    'UNSUBSCRIBE',
    'BEGIN',
    'COMMIT',
    'ACK',
    'ABORT',
    'DISCONNECT',
];

function StompSubscription(stream, session, ack) {
    this.ack = ack;
    this.session = session;
    this.stream = stream;
};

StompSubscription.prototype.send = function(stompFrame) {
    stompFrame.send(this.stream);
};

function StompQueueManager() {
    this.queues = {};
    this.msgId = 0;
    this.sessionId = 0;
};

StompQueueManager.prototype.generateMessageId = function() {
    return this.msgId++;
};

StompQueueManager.prototype.generateSessionId = function() {
    return this.sessionId++;
}

StompQueueManager.prototype.subscribe = function(queue, stream, session, ack) {
    if (!(queue in this.queues)) {
        this.queues[queue] = [];
    }
    this.queues[queue].push(new StompSubscription(stream, session, ack));
};

StompQueueManager.prototype.publish = function(queue, message) {
    if (!(queue in this.queues)) {
        return false;
    }
    var message = new StompFrame({
       command: 'MESSAGE',
       headers: {
           'destination': queue,
           'message-id': this.generateMessageId(),
       },
       body: message,
    });
    this.queues[queue].map(function(subscription) {
       subscription.send(message);
    });
    return true;
};

StompQueueManager.prototype.unsubscribe = function(queue, session) {
    if (!(queue in this.queues)) {
        return false;
    }
    // TODO: Profile this
    this.queues[queue] = this.queues[queue].filter(function(subscription) {
        return (subscription.session != session);
    });
    return true;
};

function StompStreamHandler(stream, queueManager) {
    var frameEmitter = new StompFrameEmitter(StompClientCommands);
    var authenticated = false;
    var sessionId = -1;
    var subscriptions = [];
    var transactions = {};

    stream.on('data', function (data) {
        frameEmitter.handleData(data);
    });

    stream.on('end', function () {
        subscriptions.map(function(queue) {
            queueManager.unsubscribe(queue, sessionId);
        });
        stream.end();
    });

    frameEmitter.on('frame', function(frame) {
        console.log('Received Frame: ' + frame);
        if (!authenticated && frame.command != 'CONNECT') {
            new StompFrame({
                command: 'ERROR',
                headers: {
                    message: 'Not connected',
                },
                body: 'You must first issue a CONNECT command',
            }).send(stream);
            return;
        }
        if (frame.command != 'CONNECT' && 'receipt' in frame.headers) {
            new StompFrame({
                command: 'RECEIPT',
                headers: {
                    'receipt-id': frame.headers.receipt,
                },
            }).send(stream);
        }
            switch (frame.command) {
                case 'CONNECT':
                    authenticated = queueManager.auth(frame.headers);
                    if (!authenticated) {
                        new StompFrame({
                            command: 'ERROR',
                            headers: {
                                message: 'Authentication failed.',
                            },
                            body: 'Authentication failed. Please check username and password.',
                        }).send(stream);
                    }
                    else {
                        sessionId = queueManager.generateSessionId();
                        new StompFrame({
                            command: 'CONNECTED',
                            headers: {
                                session: sessionId,
                            }
                        }).send(stream);
                    }
                    break;

                case 'SUBSCRIBE':
                    queueManager.subscribe(frame.headers.destination,
                                            stream, sessionId,
                                            frame.headers.ack || "auto");
                    break;

                case 'UNSUBSCRIBE':
                    if (!queueManager.unsubscribe(frame.headers.destination, sessionId)) {
                        new StompFrame({
                            command: 'ERROR',
                            headers: {
                                message: 'Queue does not exist'
                            },
                            body: 'Queue "' + frame.headers.destination + '" does not exist.'
                        }).send(stream);
                    }
                    break;

                case 'SEND':
                    if (!queueManager.publish(frame.headers.destination, frame.body)) {
                        new StompFrame({
                            command: 'ERROR',
                            headers: {
                                message: 'Queue does not exist'
                            },
                            body: 'Queue "' + frame.headers.destination + '" does not exist.'
                        }).send(stream);
                    }
                    break;

                case 'BEGIN':
                    if (frame.headers.transaction in transactions) {
                        new StompFrame({
                            command: 'ERROR',
                            headers: {
                                message: 'Transaction already exists',
                            },
                            body: 'Transaction "' + frame.headers.transaction + '" already exists',
                        }).send(stream);
                    }
                    else {
                        transactions[frame.headers.transaction] = [];
                    }
                    break;

                case 'COMMIT':
                    // TODO: Actually apply the transaction, this is just an abort
                    delete transactions[frame.headers.transaction]
                    break;

                case 'ABORT':
                    delete transactions[frame.headers.transaction]
                    break;

                case 'DISCONNECT':
                    subscriptions.map(function(queue) {
                        queueManager.unsubscribe(queue, sessionId);
                    });
                    stream.end();
                    break;
            }
    });

    frameEmitter.on('error', function(err) {
        var response = new StompFrame();
        response.setCommand('ERROR');
        response.setHeader('message', err['message']);
        if ('details' in err) {
            response.appendToBody(err['details']);
        }
        response.send(stream);
    });
};

function StompServer(port, queueManagerClass) {
    this.port = port;
    queueManagerClass = queueManagerClass || StompQueueManager;
    this.server = net.createServer(function(stream) {
        stream.on('connect', function() {
            console.log('Received Unsecured Connection');
            new StompStreamHandler(stream, new queueManagerClass());
        });
    });
}

function SecureStompServer(port, credentials, queueManagerClass) {
    StompServer.call(this);
    queueManagerClass = queueManagerClass || StompQueueManager;
    this.port = port;
    this.server = net.createServer(function (stream) {
        stream.on('connect', function () {
            console.log('Received Connection, securing');
            stream.setSecure(credentials);
        });
        stream.on('secure', function () {
            new StompStreamHandler(stream, new queueManagerClass());
        });
    });
}

sys.inherits(SecureStompServer, StompServer);

StompServer.prototype.listen = function() {
    this.server.listen(this.port, 'localhost');
};

StompServer.prototype.stop = function(port) {
    this.server.close();
};

exports.StompServer = StompServer
exports.SecureStompServer = SecureStompServer
exports.StompSubscription = StompSubscription
exports.StompFrame = StompFrame
