
var lib = require('./lib');
var sjcl = require('./sjcl');
var fs = require('fs');
var tls = require('tls');

var client = function(client_sec_key_base64, client_sec_key_password, ca_cert, name) {
  if (typeof(name) === 'undefined') {
    var name = 'client';
  }
  var client_log = lib.log_with_prefix(name);
  var TYPE = lib.TYPE;

  var socket;
  var protocol_state;

  function unwrap_client_sec_key() {
    var key_enc = lib.base64_to_bitarray(client_sec_key_base64);
    var salt = lib.bitarray_slice(key_enc, 0, 128);
    var key_enc_main = lib.bitarray_slice(key_enc, 128);
    var sk_der = lib.bitarray_slice(lib.KDF(client_sec_key_password, salt), 0, 128);
    var sk_cipher = lib.setup_cipher(sk_der);
    var pair_sec_bits = lib.dec_gcm(sk_cipher, key_enc_main);
    var pair_sec = sjcl.bn.fromBits(pair_sec_bits);
    return new sjcl.ecc['ecdsa'].secretKey(curve, pair_sec);
  }

  function protocol_abort() {
    client_log('protocol error');
    socket.destroy();
    protocol_state = 'ABORT';
  }

  var curve = sjcl.ecc.curves['c256'];

  var client_sec_key = unwrap_client_sec_key();

  var session_callback = null;
  var session_close_callback = null;

  function check_cert(crt) {
    // Condition 1: certificate contains these fields
    if (  crt.valid_from === undefined || 
          crt.valid_to === undefined || 
          crt.issuer === undefined ||
          crt.subject === undefined ||
          crt.fingerprint === undefined ) {
      return false;
    }
    
    // Condition 2: current time is in validity window
    var curr_time = new Date();
    if (curr_time < crt.valid_from || curr_time > crt.valid_to) {
      return false;
    }

    // Condition 3: cert will not expire in next 7 days
    var sevenDaysLater = curr_time;
    sevenDaysLater.setDate(curr_time.getDate()+7);
    if (crt.valid_to < sevenDaysLater) {
      return false;
    }

    // Condition 4: cert's subject contains these fields
    if (  crt.subject.C !== 'US' || 
          crt.subject.ST !== 'CA' ||
          crt.subject.L !== 'Stanford' || 
          crt.subject.O !== 'CS 255' ||
          crt.subject.OU !== 'Project 3' ||
          crt.subject.CN !== 'localhost' || 
          crt.subject.emailAddress !== 'cs255ta@cs.stanford.edu') {
      return false;
    }
    
    // SZTODO: From Assignment: "If any of the above checks is not satisfied, 
    // then the client should abort (via the function called protocol_abort)."
    return true;
  }

  function process_server_msg(json_data) {
    data = JSON.parse(json_data);
    switch(data.type) {
      case TYPE['CHALLENGE']:
        if (protocol_state != 'START') {
          protocol_abort();
          return;
        }

        protocol_state = 'CHALLENGE';
        var response = lib.ECDSA_sign(client_sec_key, data.message);


        // SZTODO: all messages you send over the network should consist only of strings of valid, printable ASCII characters.

        lib.send_message(socket, TYPE['RESPONSE'], response);
        break;

      case TYPE['SESSION_MESSAGE']:
        if (protocol_state != 'SUCCESS') {
          protocol_abort();
          return;
        }
        client_log('received session message: ' + data.message);
        break;

      case TYPE['SUCCESS']:
        if (protocol_state != 'CHALLENGE') {
          protocol_abort();
          return;
        }
        protocol_state = 'SUCCESS';
        if (session_callback != null) {
          session_callback();
        }
        socket.end();
        break;

      default:
        protocol_abort();
        return;
    }
  }

  client = {};

  client.connect = function(host, port, session_callback_f, session_close_callback_f) {
    var client_options = {
      ca: fs.readFileSync('./data/rootCA.pem'),
      host: host,
      port: port,
      rejectUnauthorized: true
    };
    
    session_callback = session_callback_f;
    socket = tls.connect(port, client_options, function() {
      client_log('connected to server');

      if (!check_cert(socket.getPeerCertificate())) {
        client_log('bad certificate received');
        socket.end();
      }
    });

    socket.setEncoding('utf8');
    protocol_state = 'START';

    socket.on('data', function(msg) {
      process_server_msg(msg);
    });

    socket.on('close', function() {
      protocol_state = 'END';
      client_log('connection closed');

      if (typeof(session_close_callback_f) !== 'undefined') {
        session_close_callback_f();  
      }
    });
  }

  client.get_state = function() {
    return protocol_state;
  }

  client.session_send = function(msg) {
    if (protocol_state != 'SUCCESS') {
      throw ("client: tried to send session message in state: " + protocol_state);
    }
    lib.send_message(socket, TYPE['SESSION_MESSAGE'], msg);
    client_log('sent session message: ' + msg);
  }
  
  client.disconnect = function() {
    protocol_state = 'END';
    socket.end();
  }

  return client;
}

module.exports.client = client;
