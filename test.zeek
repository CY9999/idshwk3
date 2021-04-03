global IP_TO_UA:table[addr] of set[string];
event http_all_headers(c:connection,is_orig:bool,hlist:mime_header_list)
{
	local x:set[string];
	local UA:string;
	if(hlist[2]$name=="USER-AGENT")
	{
		UA=hlist[2]$value;
		if(c$id$orig_h in IP_TO_UA)
		{
			x=IP_TO_UA[c$id$orig_h];
			add x[UA];
			IP_TO_UA[c$id$orig_h]=x;
		}
		else
		{
			add x[UA];
			IP_TO_UA[c$id$orig_h]=x;
		}
	}
}
event zeek_done()
{
	local x:addr;
	for(x in IP_TO_UA)
	{
		if(|IP_TO_UA[x]|>=3)
		{
			print cat(x,"is a proxy");
		}
	}
}
