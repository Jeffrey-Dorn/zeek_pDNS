module pDNS;
redef exit_only_after_terminate = T ;
export {
  redef enum Log::ID +={passive_dns_log};
  type TTLvector: vector of interval;
  type answersVector: vector of string; 

  type pDns_info: record {
    timeStamp: time &log;
    resp_ip: addr &log; #will be vector of
    query:  string &log; #will be vector of
    qTypeName: string &log;
    TTLS: TTLvector &log &default = TTLvector(1 sec);
    RA: bool &log;
    answers: answersVector &log &default = answersVector("default");
    first: time &log;
    last : time &log;
    seen_count : count &log;
    erase: bool;
  }; 
  type Idx: record {
   resp_ip: addr;
  };
  global log_entry: function(t: table[addr] of pDns_info, idx: addr): interval;
  global entries: table[addr] of pDNS::pDns_info &write_expire = 10 sec &expire_func=log_entry &redef;
}

event zeek_init(){
  #print db;
  Input::add_table([$source = "tmp/pDNS_info",
    $name ="pDNS_infIdx,o",
    $idx = Idx,
    $val = pDns_info,
    $destination = entries,
    $reader=Input::READER_SQLITE,
    $config= table(["query"] = "SELECT * FROM pDNS;")
  ]);

  #sets up logging framework for sqlite
  const config_json = table(
    ["use_json"]="T",
    ["json_timestamps"]="JSON::TS_EPOCH",
    ["tablename"]= "pDNS"); 
  
  Log::create_stream(pDNS::passive_dns_log, [$columns = pDns_info, $path ="pdns"]);
  local filter : Log::Filter=[
    $name = "sqlite",
    $path = "tmp/pDNS_info",
    $config = config_json,
    $writer = Log::WRITER_SQLITE
  ];
  Log::add_filter(pDNS::passive_dns_log, filter);

}

event Input::end_of_data(name: string, source: string)
    {
    if ( name != "pDNS_info" )
        return;

    # now all data is in the table
    print "Hosts list has been successfully imported";

    # List the users of one host.
        for (a in entries)
            print entries[a]$resp_ip;
    }

event DNS::log_dns(dnsRcd: DNS::Info){
  if(dnsRcd$id$resp_h in entries && dnsRcd?$query && dnsRcd?$answers && dnsRcd?$qtype_name){
    ++entries[dnsRcd$id$resp_h]$seen_count;
    entries[dnsRcd$id$resp_h]$last = dnsRcd$ts;
    entries[dnsRcd$id$resp_h]$answers+=dnsRcd$answers;
    entries[dnsRcd$id$resp_h]$TTLS +=dnsRcd$TTLs;
    #should query be a vector of past queries  YES
  }
  else{
    if(dnsRcd?$query && dnsRcd?$answers && dnsRcd?$qtype_name){#creates new entry if needed 
      local info :pDns_info = [$timeStamp = dnsRcd$ts, $resp_ip = dnsRcd$id$resp_h, $query = dnsRcd$query, $qTypeName = dnsRcd$qtype_name, $TTLS= dnsRcd$TTLs ,$RA = dnsRcd$RA , $answers =dnsRcd$answers, $first = dnsRcd$ts, $last = dnsRcd$ts, $seen_count =1, $erase = F];
    entries[dnsRcd$id$resp_h] = info; 
    }
  }
  }

function log_entry(t: table[addr] of pDns_info, idx: addr): interval { 
  Log::write(pDNS::passive_dns_log, t[idx]);
  if( t[idx]$erase== F){
    t[idx]$erase = T;
    return 5 sec;# should be 1 hr
    }
  else{
    return 0 sec;
  }
}
