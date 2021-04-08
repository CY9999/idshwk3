global p :table[addr] of set[string]= {};

event http_header(c: connection, is_orig: bool, name :string, value :string){
  local Addr :addr=c$id$orig_h;
  local UserAgent :string=to_lower(value);
  if(name=="USER-AGENT"){
    if(Addr in p){
      add p[Addr][UserAgent];
    }
    else{
      p[Addr]=set(UserAgent);
    }
  }
}

event zeek_done(){
  local s :string=" is a proxy";
  for(i in p){
    if((|p[i]|)>=3)
      print i,s;
  }
}
