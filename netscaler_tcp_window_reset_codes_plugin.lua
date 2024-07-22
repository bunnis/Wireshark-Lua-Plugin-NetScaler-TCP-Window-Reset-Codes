----------------------------------------
-- script-name: netscaler_tcp_window_reset_codes_plugin.lua
-- Author: Pedro Silva - July 2024
-- Copyright (c) 2024, Pedro Silva
-- https://github.com/bunnis/Wireshark-Lua-Plugin-NetScaler-TCP-Window-Reset-Codes
-- Wireshark LUA script for adding support for Citrix NetScaler TCP Window Reset Codes
-- Source https://support.citrix.com/article/CTX200852/citrix-adc-netscaler-reset-codes-reference
-- 2024/07/17 - Cleaned code, published repository
-- 2024/07/10 - First draft


-- resources
-- https://mika-s.github.io/wireshark/lua/dissector/2018/12/16/creating-a-wireshark-dissector-in-lua-4.html
-- https://gitlab.com/wireshark/wireshark/-/wikis/Lua/Examples#a-dissector-tutorial-script from Hadriel Kaplan
-- we use the code from https://wiki.wireshark.org/Lua/Dissectors#chained-dissectors 
-- to override the default TCP disssector and write our new field in the TCP Tree
-- we figure out which name the dissector has with the below function
-- https://osqa-ask.wireshark.org/questions/32288/can-over-ethernet-lua-dissector/
-- local t = Dissector.list()
-- for _,name in ipairs(t) do
-- print(name)
-- end
--local ip_proto_table = DissectorTable.get("ip.proto")
--local original_tcp_dissector = ip_proto_table:get_dissector(6)
----------------------------------------
local debug_enabled = 0
local dprint = function() end
local function set_debug_level()
    if debug_enabled > 0 then
        dprint = function(...)
            print(table.concat({"Lua:", ...}," "))
        end
    end
end
-- call it now
set_debug_level()

dprint("Wireshark version = ", get_version())
dprint("Lua version = ", _VERSION)

-- Reset code to description table
-- Define a new protocol, but don't register it yet
local nstrace_tcp_rst_window_error_code = Proto("nstrace_tcp_rst_window_error_code", "NetScaler TCP Reset Window Codes")

-- Define the fields
local f_tcp_rst_window_error_code_text = ProtoField.string("nstrace.tcp.rst.window_code.text", "Description") -- we use this field so that the description can be copied in the cases it is truncated. 
-- Add our fields
-- nstrace_tcp_rst_window_error_code.fields = {f_custom_string}

-- Define field extractors
-- using tcp.window_size_value instead of tcp.window_size allows us to ignore window scaling into our final window value
local f_tcp_window_size = Field.new("tcp.window_size_value")
local f_tcp_flags_reset = Field.new("tcp.flags.reset")

-- Define expert fields
-- local expert_field_text = ProtoExpert.new("nstrace.tcp.rst.window_code.text", "NetScaler TCP Reset - Window Error Description", expert.group.COMMENTS_GROUP, expert.severity.COMMENT)
local expert_field_code = ProtoExpert.new("nstrace.tcp.rst.window_code.code", "NetScaler TCP Reset - Window Error Code", expert.group.COMMENTS_GROUP, expert.severity.COMMENT)

-- Add our expert fields
nstrace_tcp_rst_window_error_code.experts = { expert_field_code }

-- Define the dictionary table
-- Source https://support.citrix.com/article/CTX200852/citrix-adc-netscaler-reset-codes-reference
-- Dates of source: Created: 31 Mar 2015 | Modified: 21 Jan 2023
-- Date of last dictionary update: 2024/07/11
-- NOTE: when updating don't just overwrite the dictionary, the definitions below are more polished than the ones in the CTX.
local window_rst_code_dict = {
    [8196] = "SSL bad record.",
    [8201] = "NSDBG_RST_SSTRAY: This reset code is triggered when packets are received on a socket that has already been closed. For example, if a client computer continues transmitting after receiving a RST code for other reasons, then it receives this RST code for the subsequent packets.",
    [8202] = "NSDBG_RST_CSTRAY: This code is triggered when the NetScaler appliance receives data through a connection, which does not have a PCB, and its SYN cookie has expired.",
    [8204] = "Client retransmitted SYN with the wrong sequence number.",
    [8205] = "ACK number in the final ACK from peer during connection establishment is wrong.",
    [8206] = "Received a bad packet in TCPS_SYN_SENT state (non RST packet). Usually happens if the 4 tuples are reused and you receive packet from the old connection.",
    [8207] = "Received SYN on established connection which is within the window. Protects from spoofing attacks.",
    [8208] = "Resets the connection when you receive more than the configured value of duplicate retransmissions.",
    [8209] = "Could not allocate memory for the packet, system out of memory.",
    [8210] = "HTTP DoS protection feature error, bad client request.",
    [8211] = "NSDBG_RST_ZSSSR: This code refers to an idle timeout or a zombie timeout. This code is set by the zombie connection cleanup routine, a connection has timed out. When the status of a service is down, existing TCP connections to that service are reset with this code (TCP window size 9300/9301, zombie timer). If the NetScaler appliance receives a segment from one of these connections, which is already reset, send another reset (TCP window size 8201, stray packet).",
    [8212] = "Stray packet (no listening service or listening service is present but SYN cookie does not match or there is no corresponding connection information). 8212 is specifically for SYN stray packets.",
    [8213] = "Sure Connect feature, bad client sending post on connection which is closing.",
    [8214] = "MSS sent in SYN exceeded the MSS corresponding to NIC MTU and/or VLAN MTU.",
    [9100] = "NSDBG_RST_ORP: This code refers to an orphan HTTP connection. Probably, a connection where data is initially seen either from the server or client, but stopped because of some reason, without closing the TCP session. It indicates that the client request was not properly terminated. Therefore, the NetScaler appliance waits for the request to be completed. After a timeout, the NetScaler appliance resets the connection with the code 9100.",
	[9201] = "HTTP connection multiplexing error. Server sent response packets belonging to previous transaction.",
	[9202] = "NSDBG_RST_LERRCDM:  CDM refers to Check Data Mixing. This reset code is set when there is a TCP sequence mismatch in the first data packet, arriving from a recently reused server connection.",
	[9203] = "NSDBG_RST_CLT_CHK_MIX: This code refers to the server sending a FIN for a previous client over a reused connection.",
	[9205] = "NSDBG_RST_CHUNK_FAIL: This code indicates that the NetScaler appliance experienced issues with the chunked encoding in the HTTP response from the server.",
	[9206] = "HTTP tracking failed due to invalid HTTP request/response header.",
	[9207] = "Invalid header reassembly parsing.",
	[9208] = "Incomplete response processing error, see incompHdrDelay setting httpprofiles.",
	[9209] = "Chunk tracking failed.",
	[9210] = "Corrupt packets.",
    [9212] = "HTTP Invalid request.",
    [9214] = "Cache res store failed.",
    [9216] = "Cache async no memory.",
    [9217] = "HTTP state machine error because of more than content length body.",
    [9218] = "Terminated due to extra orphan data.",
    [9219] = "NSB allocation failure.",
    [9220] = "Cannot allocate new NSB and so many other reasons.",
    [9221] = "vurl comes with a domain shard that’s no longer valid.",
    [9222] = "This is sent when the response is RFC non-compliant. The issue is caused by both Content-Length and Transfer-Encoding in response being invalid, which may lead to a variety of attacks and leads to the reset.",
    [9300] = "NSDBG_RST_ZSSSR: This code refers to an idle timeout or a zombie timeout. This code is set by the zombie connection cleanup routine, a connection has timed out. When the status of a service is down, existing TCP connections to that service are reset with this code (TCP window size 9300/9301, zombie timer). If the NetScaler appliance receives a segment from one of these connections, which is already reset, send another reset (TCP window size 8201, stray packet).",
    [9301] = "NSDBG_RST_ZSSSR: This code refers to an idle timeout or a zombie timeout. This code is set by the zombie connection cleanup routine, a connection has timed out. When the status of a service is down, existing TCP connections to that service are reset with this code (TCP window size 9300/9301, zombie timer). If the NetScaler appliance receives a segment from one of these connections, which is already reset, send another reset (TCP window size 8201, stray packet).",
    [9302] = "NSDBG_RST_ZSSSR: This code refers to an idle timeout or a zombie timeout. This code is set by the zombie connection cleanup routine, a connection has timed out. When the status of a service is down, existing TCP connections to that service are reset with this code (TCP window size 9300/9301, zombie timer). If the NetScaler appliance receives a segment from one of these connections, which is already reset, send another reset (TCP window size 8201, stray packet).",
    [9303] = "NSDBG_RST_ZSSSR: This code refers to an idle timeout or a zombie timeout. This code is set by the zombie connection cleanup routine, a connection has timed out. When the status of a service is down, existing TCP connections to that service are reset with this code (TCP window size 9300/9301, zombie timer). If the NetScaler appliance receives a segment from one of these connections, which is already reset, send another reset (TCP window size 8201, stray packet).",
    [9304] = "NSDBG_RST_LINK_GIVEUPS: This reset code might be part of a backend-persistence mechanism, which is used to free resources on the NetScaler. By default, the NetScaler uses a zero window probe 7 times before giving up and resetting the connection. By disabling this mechanism, the appliance holds the sessions without this limit. The following is the command to disable the persistence probe limit: root@ns# nsapimgr -ys limited_persistprobe=0 The default value is 1, which limits to 7 probes, which is around 2 minutes. Setting the value to zero disables it and keeps the session open as long as the server sends an ACK signal in response to the probes.",
    [9305] = "Server sent back ACK to our SYN (ACK number did not match).",
    [9306] = "TCP buffering is undone due to duplicate TPCB enablement.",
    [9307] = "Small window protection feature resetting the connection.",
    [9308] = "Small window protection feature resetting the connection.",
    [9309] = "Small window protection feature resetting the connection.",
    [9310] = "TCP KA probing failed.",
    [9311] = "DHT retry failed.",
    [9400] = "Reset server connection which are in reusepool and are not reusable because of TCP or Session level properties. Usually this is done when we need to open new connections but there is limit on connection we can open to the server and there are some already built up connections which are not reusable.",
    [9401] = "When you reach maximum system capacity flushing existing connections based time order to accommodate new connections. Or when we remove an configured entity which as associated connections those connection will be reset.",
    [9450] = "SQL HS failed.",
    [9451] = "SQL response failed.",
    [9452] = "SQL request list failed.",
    [9453] = "SQL UNK not linked.",
    [9454] = "SQL NSB hold failed.",
    [9455] = "SQL Server First Packet.",
    [9456] = "SQL Login response before request.",
    [9457] = "SQL server login failed.",
    [9458] = "SQL no memory.",
    [9459] = "SQL bad server.",
    [9460] = "SQL link failed.",
    [9600] = "Reset when Number of packets with Sequence ACK mismatch > nscfg_max_orphan_pkts.",
    [9601] = "Reset when Number of data packets with Sequence ACK mismatch > nscfg_max_orphan_pkts.",
    [9602] = "When SSL VPN CS probe limit exceeded.",
    [9700] = "NSDBG_RST_PASS: This code indicates that the NetScaler appliance receives a TCP RST code from either the client or the server, and is transferring it. For example, the back end server sends a RST code, and the NetScaler appliance forwards it to the client with this code.",
    [9701] = "NSDBG_RST_NEST / NSDBG_RST_ACK_PASS: The NetScaler software release 9.1 and the later versions, this code indicates #define NSBE_DBG_RST_ACK_PASS. It indicates that a RST code was forwarded as in the preceding RST code 9700, and the ACK flag was also set.",
    [9702] = "The data received after FIN is received.",
    [9704] = "Reset when NSB dropped due to hold limit or error in transaction etc.",
    [9800] = "NSDBG_RST_PROBE: This connections used for monitoring the service are reset due to timeout.",
    [9810] = "When responses match the configured NAI status code.",
    [9811] = "NSDBG_RST_ERRHANDLER: This reset code is used with SSL. After sending a Fatal Alert, the NetScaler sends a RST packet with this error code. If the client does not display any supported ciphers to the NetScaler appliance, the appliance sends a Fatal Alert and then this RST packet.",
    [9812] = "Connection flushing because existing IP address is removed from the configuration.",
    [9813] = "Closing the SSF connection.",
    [9814] = "NSDBG_RST_PETRIGGER: This reset code is used when a request or response matches a Policy Engine policy, whose action is RESET.",
    [9816] = "Bad SSL record.",
    [9817] = "SSL connection received at the time of bound certificate changing (configuration change).",
    [9818] = "Bad SSL header value.",
    [9819] = "Reset on failing to allocate memory for SPCB.",
    [9820] = "SSL card operation failed.",
    [9821] = "SSL feature disabled, reset the connection.",
    [9822] = "SSL cipher changed, flush the connection created for old cipher.",
    [9823] = "Reset when the NSC_AAAC cookie is malformed in a request or /vpn/apilogin.html request does not have a query part, memory allocation failures in certificate processing.",
    [9824] = "Reset on AAA orphan connections.",
    [9825] = "DBG_WRONG_GSLBRECDLEN: This code is a GSLB MEP error reset code, typically between mixed versions.",
    [9826] = "Not enough memory for NET buffers.",
    [9827] = "Reset on SSL config change.",
    [9829] = "Reset on GSLB other site down or out of reach.",
    [9830] = "Reset on sessions matching ACL DENY rule.",
    [9831] = "Use it if no application data exist, but required.",
    [9832] = "Application error.",
    [9833] = "Fatal SSL error.",
    [9834] = "Reset while flushing all SPCB, during FIPS or HSM init.",
    [9835] = "DTLS record too large.",
    [9836] = "DTLS record zero length.",
    [9837] = "SSLV2 record too large.",
    [9838] = "NSBE_DBG_RST_SSL_BAD_RECORD: This code refers to error looking up SSL record when handling a request or a response.",
    [9839] = "SSL MAX NSB hold limit reached.",
    [9841] = "SSL/DTLS split packet failure.",
    [9842] = "SSL NSB allocation failure.",
    [9843] = "Monitor wide IP probe.",
    [9844] = "SSL reneg max NSB limit reached or alloc failure.",
    [9845] = "Reset on Appsec policy.",
    [9846] = "Delta compression aborted or failed.",
    [9847] = "Delta compression aborted or failed.",
    [9848] = "Reset on connection accepted during configuration change(SSL).",
    [9849] = "Reset on GSLB conflict due to misconfiguration.",
    [9850] = "DNS TCP connection untrackable due to failure of compact NSB, etc.",
    [9851] = "DNS TCP failure (invalid payload, length, etc).",
    [9852] = "RTSP (ALG) session handling error.",
    [9853] = "MSSQL Auth response error.",
    [9854] = "Indirect GSLB sites tried to establish connection",
    [9855] = "For HTTP/SSL vservers, SO (Surge Queue Overflow.) threshold has reached.",
    [9856] = "Reset on Appfw ASYNC failure.",
    [9857] = "Reset on Flushing HTTP waiting PCB.",
    [9858] = "Reset on Rechunk abort.",
    [9859] = "A new client connection request was made deferrable by server on the label.",
    [9860] = "The pcb->link of this connection was cleaned for some reason, so resetting this PCB.",
    [9861] = "Connection on a push vserver, when push disabled on client vserver.",
    [9862] = "Reset to Client as it resulted in duplicate server connection.",
    [9863] = "Reset to old connection when new connection is established and old one is still not freed.",
    [9864] = "CVPN HINFO restore failed.",
    [9865] = "CVPN MCMX error.",
    [9866] = "URL policy transform error.",
    [9868] = "MSSQL login errors.",
    [9870] = "SQL login parse error.",
    [9871] = "MSSQL memory allocation failure.",
    [9872] = "Websocket upgrade request dropped due to websocket disabled in http profile.",
    [9873] = "Agsvc MCMX failure.",
    [9874] = "NSB hold limit reached.",
    [9875] = "Client connection is closed, send RST to server.",
    [9876] = "One to many link failed.",
    [9877] = "Reset for CEA on client PCB.",
    [9878] = "CEA untrackable, send RST to Client.",
    [9879] = "Parsing failed.",
    [9880] = "Memory alloc failure.",
    [9881] = "Reset on Diameter message without CE.",
    [9882] = "Reset to Client if no pending requests.",
    [9883] = "Link PCB fail reset to client on CEA.",
    [9884] = "Reset to Server PCB.",
    [9885] = "SIP Content header is missing. | 	Diameter reset on bad ACK.",
    [9886] = "Reset on VPN ng binding miss.",
    [9887] = "Reset on failed to send a request to broker (VPN).",
    [9888] = "Reset to AAA client if Cluster sync in progress.",
    [9889] = "Reset on missing dynamic processing context (LUA).",
    [9890] = "Rewrite feature disabled when blocked on response side.",
    [9900] = "PI reset.",
    [9901] = "Cache buffer large data error.",
    [9902] = "HTML injection connection abort.",
    [9903] = "GSLB feature is disabled. Donot accept any connections and close any existing ones.",
    [9904] = "Reset on AAA error.",
    [9905] = "Database not responding.",
    [9906] = "Local GSLB sites have been removed, send RST.",
    [9911] = "HTTP incomplete due to no available memory.",
    [9912] = "HTTP link incomplete due to no available memory.",
    [9913] = "Send RST for SPDY errors.",
    [9914] = "Cache Response error/AAA.",
    [9915] = "Speedy split packet at header failed.",
    [9951] = "SSL incomplete record.",
    [9952] = "Reset on SSL FATAL ALERT RCVD.",
    [9953] = "Reset on triggering of timeout action.",
    [9956] = "QOS incomplete POST handling error.",
    [9957] = "AppQoS Persistent sercvice is down.",
    [9958] = "Not used+C187:C199.",
    [9959] = "Not used.",
    [9960] = "MPTCP options error.",
    [9961] = "MP join SYN reset.",
    [9962] = "MP join FINAL ACK reset.",
    [9963] = "MPTCP checksum failure.",
    [9964] = "Invalid Client or NS key.",
    [9965] = "MPTCP, established SF replaced.",
    [9966] = "MPTCP RSSF filter failure.",
    [9967] = "MPTCP plain ACK fallback failure.",
    [9968] = "MPTCP fast close received.",
    [9969] = "MPTCP, if NS in fallback mode, DSS should only for infinite map.",
    [9970] = "BW Connection Close.",
    [9971] = "MPTCP invalid/bad MAP.",
    [9972] = "MPTCP reset if multiple SFs are present.",
    [9973] = "Reset on rest of SF after fallback to infinite map as only one SF should be present.",
    [9974] = "RST terminated at TCP layer.",
    [9975] = "PCB waitQ insertion failed.",
    [9976] = "MPTCP MAX retries on KA probes has reached.",
    [9977] = "MPTCP token collision is found.",
    [9978] = "MPTCP SYN retries reached MAXretries.",
    [9979] = "MPTCP subflow FIN received or any other signals received on pre est SF.",
    [9980] = "Reset on MPTCP close.",
    [9981] = "Closing auditlog connection.",
    [9982] = "invalid syn/ack/seq is received for NS's SYN+TFOC+DATA.",
    [9983] = "MPTCP invalid payload size.",
    [10000] = "ICA parse error.",
    [10001] = "ICA link parse error.",
    [10002] = "ICA no available memory.",
    [10003] = "ICA link no available memory.",
    [10004] = "Kill an ICA connection.",
    [10005] = "MPTCP SYN retries reached MAXretries.",
    [10006] = "Kill an RDP connection.",
    [10016] = "SMPP no memory available.",
    [10017] = "SMPP reset if no pending requests.",
    [10018] = "SMPP unknown error.",
    [10019] = "SMPP: Bind to client failed.",
    [10020] = "SMPP: NSB hold limit reached.",
    [10022] = "SMPP: Bind response on client.",
    [10023] = "SMPP: Parsing failed.",
    [10024] = "SMPP: link failed.",
    [10026] = "SMPP: MSG without bind or not request message after bind.",
    [10027] = "SSL: HSM operation failed.",
    [10028] = "SSL: HSM error client.",
    [10029] = "SSL: Hit the ratelimit.",
    [10030] = "Connection breached maximum packet credits configured.",
    [10032] = "SIPALG: Header parsing failed.",
    [10033] = "SIPALG: Body parsing failed.",
    [10034] = "SIPALG: SIP header failure.",
    [10035] = "SIPALG: SDP header failure.",
    [10036] = "SIPALG: Remaining IP replacement failure.",
    [10037] = "SIPALG: Length replacement failure.",
    [10038] = "SIPALG: BA insertion failed.",
    [10039] = "SIPALG: DHT failure.",
    [10040] = "SIPALG: Post translation ops failed.",
    [10042] = "SIPALG: Pre translation ops failed."
}

dprint("Citrix NetScaler Reset Code Reference script loaded")

-- Dissection function
function nstrace_tcp_rst_window_error_code.dissector(buffer, pinfo, tree)
    -- Pseudo
	-- 1 - Ensure packet is of type TCP
	-- 2 - Ensure TCP RST flag is set
	-- 2a - (TODO) One could extract nstrace.* fields and confirm this is a .pcap from the netscalear. 
	--      However, the capture doesn't need to be done at the netscaler to see these reset codes
	-- 3 - Extract Window value
	-- 4 - Check if value is on the table, if it's found then we add our new TreeItem
   dprint("called dissector")
	local tcp_dissector_table = DissectorTable.get("tcp.port")
    local tcp_dissector = tcp_dissector_table:get_dissector(pinfo.dst_port)
	-- Ensure the packet is TCP
	if tcp_dissector == nil 
	then 
		return 
    end
	dprint("packet is TCP")	
	-- Check if the TCP reset flag is set, returns 1 if True, 0 if False
    local tcp_reset_flag = f_tcp_flags_reset()
	dprint("TCP reset flag is", tostring(tcp_reset_flag))
    
	
	if ( tostring(tcp_reset_flag) == "1" ) or ( tostring(tcp_reset_flag) == 'True' ) then  -- both checks fix LUA issues with WIreshark 4.0.10 and 4.2.6
		dprint("extracting window_size")
		-- Extract TCP Window Size
		local window_size = tonumber(tostring(f_tcp_window_size()))
		
		-- Look up the description based on window size
		local window_description = window_rst_code_dict[window_size]
		dprint("window_size is ")
		-- If a description was found, add the tree
		if window_description == nil 
		then 
			return 
		else
			dprint("adding netscaler window error code tree")
			local subtree = tree:add(nstrace_tcp_rst_window_error_code, buffer(), "NetScaler TCP Reset - Window Error Code")
			subtree:add(f_tcp_rst_window_error_code_text, window_description)
			subtree:add_proto_expert_info(expert_field_code,tostring(window_size))
		end
	
		
	end	
	
end


-- Register the dissector and take its place in the dissector table
-- ip_proto_table:add(6, nstrace_tcp_rst_window_error_code)

-- Register the post-dissector 
register_postdissector(nstrace_tcp_rst_window_error_code)