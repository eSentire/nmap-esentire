local nmap = require "nmap"
local shortport = require "shortport"
local sslcert = require "sslcert"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"
local tls = require "tls"

description = [[
Discovery of ephemeral Diffie-Hellman parameters for SSL/TLS services.

This script simulates SSL/TLS handshakes using ciphersuites that have ephemeral
Diffie-Hellman as the key exchange algorithm.

Diffie-Hellman MODP group parameters are extracted and analyzed for use of common
primes and vulnerability to LOGJAM precomputation attacks.

Opportunistic STARTTLS sessions are established on services that support them.
]]

--
-- @usage
-- nmap --script ssl-dh-params <target>
--
-- @output
-- Host script results:
-- | ssl-dh-params: 
-- |   LOGJAM: Vulnerable to DH precomputation attacks!
-- |   MODP PRIME #1: 
-- |     Source: mod_ssl 2.2.x/Hardcoded 512-bit prime
-- |     Length: 512 bits
-- |     Value: 
-- |       9fdb8b8a004544f0045f1737d0ba2e0b274cdf1a9f588218fb435316a16e3741
-- |       71fd19d8d8f37c39bf863fd60e3e300680a3030c6e4c3757d08f70e6aa871033
-- |   MODP PRIME #2: 
-- |     Source: mod_ssl 2.2.x/Hardcoded 1024-bit prime
-- |     Length: 1024 bits
-- |     Value: 
-- |       d67de440cbbbdc1936d693d34afd0ad50c84d239a45f520bb88174cb98bce951
-- |       849f912e639c72fb13b4b4d7177e16d55ac179ba420b2a29fe324a467a635e81
-- |       ff5901377beddcfd33168a461aad3b72dae8860078045b07a7dbca7874087d15
-- |_      10ea9fcc9ddd330507dd62db88aeaa747de0f4d6e2bd68b0e7393e0f24218eb3

author = "Jacob Gajek"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}


-- Full-strength ephemeral Diffie-Hellman key exchange variants
local DHE_ALGORITHMS = {
	"DH_anon",
	"DHE_RSA",
	"DHE_DSS"
}

-- Export-grade ephemeral Diffie-Hellman key exchange variants
local DHE_ALGORITHMS_EXPORT = {
	"DH_anon_EXPORT",
	"DHE_RSA_EXPORT",
	"DHE_DSS_EXPORT",
	"DHE_DSS_EXPORT1024"
}

-- Helper function to convert hex string to byte array
local function fromhex(hexstr)
	local buf = {}
	for byte in string.gmatch(hexstr, "%s*(%x%x)") do
		buf[#buf + 1] = string.char(tonumber(byte, 16))
	end
	return table.concat(buf)
end

-- Common Diffie-Hellman primes
local DHE_PRIMES = {
	["mod_ssl 2.0.x/Hardcoded 512-bit prime"] = fromhex([[
		D4BCD524 06F69B35 994B88DE 5DB89682 C8157F62 D8F33633 EE5772F1 1F05AB22
		D6B5145B 9F241E5A CC31FF09 0A4BC711 48976F76 795094E7 1E790352 9F5A824B
	]]),

	["mod_ssl 2.0.x/Hardcoded 1024-bit prime"] = fromhex([[
		E6969D3D 495BE32C 7CF180C3 BDD4798E 91B78182 51BB055E 2A206490 4A79A770
		FA15A259 CBD523A6 A6EF09C4 3048D5A2 2F971F3C 20129B48 000E6EDD 061CBC05
		3E371D79 4E5327DF 611EBBBE 1BAC9B5C 6044CF02 3D76E05E EA9BAD99 1B13A63C
		974E9EF1 839EB5DB 125136F7 262E56A8 871538DF D823C650 5085E21F 0DD5C86B
	]]),

	["mod_ssl 2.2.x/Hardcoded 512-bit prime"] = fromhex([[
		9FDB8B8A 004544F0 045F1737 D0BA2E0B 274CDF1A 9F588218 FB435316 A16E3741
		71FD19D8 D8F37C39 BF863FD6 0E3E3006 80A3030C 6E4C3757 D08F70E6 AA871033
	]]),

	["mod_ssl 2.2.x/Hardcoded 1024-bit prime"] = fromhex([[
		D67DE440 CBBBDC19 36D693D3 4AFD0AD5 0C84D239 A45F520B B88174CB 98BCE951
		849F912E 639C72FB 13B4B4D7 177E16D5 5AC179BA 420B2A29 FE324A46 7A635E81
		FF590137 7BEDDCFD 33168A46 1AAD3B72 DAE88600 78045B07 A7DBCA78 74087D15
		10EA9FCC 9DDD3305 07DD62DB 88AEAA74 7DE0F4D6 E2BD68B0 E7393E0F 24218EB3
	]]),

	["nginx/Hardcoded 1024-bit prime"] = fromhex([[
		BBBC2DCA D8467490 7C43FCF5 80E9CFDB D958A3F5 68B42D4B 08EED4EB 0FB3504C
		6C030276 E710800C 5CCBBAA8 922614C5 BEECA565 A5FDF1D2 87A2BC04 9BE67780
		60E91A92 A757E304 8F68B076 F7D36CC8 F29BA5DF 81DC2CA7 25ECE662 70CC9A50
		35D8CECE EF9EA027 4A63AB1E 58FAFD49 88D0F65D 146757DA 071DF045 CFE16B9B
	]]),

	["Java 7/Hardcoded 768-bit prime"] = fromhex([[
		E9E64259 9D355F37 C97FFD35 67120B8E 25C9CD43 E927B3A9 670FBEC5 D8901419
		22D2C3B3 AD248009 3799869D 1E846AAB 49FAB0AD 26D2CE6A 22219D47 0BCE7D77
		7D4A21FB E9C270B5 7F607002 F3CEF839 3694CF45 EE3688C1 1A8C56AB 127A3DAF
	]]),

	["OpenSSL/Hardcoded 512-bit prime"] = fromhex([[
		DA583C16 D9852289 D0E4AF75 6F4CCA92 DD4BE533 B804FB0F ED94EF9C 8A4403ED
		574650D3 6999DB29 D776276B A2D3D412 E218F4DD 1E084CF6 D8003E7C 4774E833
	]]),

	["OpenSSL/Hardcoded 1024-bit prime"] = fromhex([[
		97F64261 CAB505DD 2828E13F 1D68B6D3 DBD0F313 047F40E8 56DA58CB 13B8A1BF
		2B783A4C 6D59D5F9 2AFC6CFF 3D693F78 B23D4F31 60A9502E 3EFAF7AB 5E1AD5A6
		5E554313 828DA83B 9FF2D941 DEE95689 FADAEA09 36ADDF19 71FE635B 20AF4703
		64603C2D E059F54B 650AD8FA 0CF70121 C74799D7 587132BE 9B999BB9 B787E8AB
	]]),

	["OpenSSL/Hardcoded 2048-bit prime #1"] = fromhex([[
		ED928935 824555CB 3BFBA276 5A690461 BF21F3AB 53D2CD21 DAFF7819 1152F10E
		C1E255BD 686F6800 53B9226A 2FE49A34 1F65CC59 328ABDB1 DB49EDDF A71266C3
		FD210470 18F07FD6 F7585119 72827B22 A934181D 2FCB21CF 6D92AE43 B6A829C7
		27A3CB00 C5F2E5FB 0AA45985 A2BDAD45 F0B3ADF9 E08135EE D983B3CC AEEAEB66
		E6A95766 B9F128A5 3F2280D7 0BA6F671 939B810E F85A90E6 CCCA6F66 5F7AC010
		1A1EF0FC 2DB6080C 6228B0EC DB8928EE 0CA83D65 94691669 533C5360 13B02BA7
		D48287AD 1C729E41 35FCC27C E951DE61 85FC199B 76600F33 F86BB3CA 520E29C3
		07E89016 CCCC0019 B6ADC3A4 308B33A1 AFD88C8D 9D01DBA4 C4DD7F0B BD6F38C3
	]]),

	["OpenSSL/Hardcoded 2048-bit prime #2"] = fromhex([[
		AED037C3 BDF33FA2 EEDC4390 B70A2089 7B770175 E9B92EB2 0F8061CC D4B5A591
		723C7934 FDA9F9F3 274490F8 50647283 5BE05927 1C4F2C03 5A4EE756 A36613F1
		382DBD47 4DE8A4A0 322122E8 C730A83C 3E4800EE BD6F8548 A5181711 BA545231
		C843FAC4 175FFAF8 49C440DB 446D8462 C1C3451B 49EFA829 F5C48A4C 7BAC7F64
		7EE00015 1AA9ED81 101B36AB 5C39AAFF EC54A3F8 F97C1B7B F406DCB4 2DC092A5
		BAA06259 EFEB3FAB 12B42698 2E8F3EF4 B3F7B4C3 302A24C8 AA4213D8 45035CE4
		A8ADD31F 816616F1 9E21A5C9 5080597F 8980AD6B 814E3585 5B79E684 4491527D
		552B72B7 C78D8D6B 993A736F 8486B305 88B8F1B8 7E89668A 8BD3F13D DC517D4B
	]]),

	["OpenSSL/Hardcoded 4096-bit prime"] = fromhex([[
		FEEAD19D BEAF90F6 1CFCA106 5D69DB08 839A2A2B 6AEF2488 ABD7531F BB3E462E
		7DCECEFB CEDCBBBD F56549EE 95153056 8188C3D9 7294166B 6AABA0AA 5CC8555F
		9125503A 180E9032 4C7F39C6 A3452F31 42EE72AB 7DFFC74C 528DB6DA 76D9C644
		F55D083E 9CDE74F7 E742413B 69476617 D2670F2B F6D59FFC D7C3BDDE ED41E2BD
		2CCDD9E6 12F1056C AB88C441 D7F9BA74 651ED1A8 4D407A27 D71895F7 77AB6C77
		63CC00E6 F1C30B2F E7944692 7E74BC73 B8431B53 011AF5AD 1515E63D C1DE83CC
		802ECE7D FC71FBDF 179F8E41 D7F1B43E BA75D5A9 C3B11D4F 1B0B5A09 88A9AACB
		CCC10512 26DC8410 E41693EC 8591E31E E2F5AFDF AEDE122D 1277FC27 0BE4D25C
		1137A58B E961EAC9 F27D4C71 E2391904 DD6AB27B ECE5BD6C 64C79B14 6C2D208C
		D63A4B74 F8DAE638 DBE2C880 6BA10773 8A8DF5CF E214A4B7 3D03C912 75FBA572
		8146CE5F EC01775B 74481ADF 86F4854D 65F5DA4B B67F882A 60CE0BCA 0ACD157A
		A377F10B 091AD0B5 68893039 ECA33CDC B61BA8C9 E32A87A2 F5D8B7FD 26734D2F
		09679235 2D70ADE9 F4A51D84 88BC57D3 2A638E0B 14D6693F 6776FFFB 355FEDF6
		52201FA7 0CB8DB34 FB549490 951A701E 04AD49D6 71B74D08 9CAA8C0E 5E833A21
		291D6978 F918F25D 5C769BDB E4BB72A8 4A1AFE6A 0BBAD18D 3EACC7B4 54AF408D
		4F1CCB23 B9AE576F DAE2D1A6 8F43D275 741DB19E EDC3B81B 5E56964F 5F8C3363
	]]),

	["RFC2409/Oakley Group 1"] = fromhex([[
		FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1 29024E08 8A67CC74
		020BBEA6 3B139B22 514A0879 8E3404DD EF9519B3 CD3A431B 302B0A6D F25F1437
		4FE1356D 6D51C245 E485B576 625E7EC6 F44C42E9 A63A3620 FFFFFFFF FFFFFFFF
	]]),

	["RFC2409/Oakley Group 2"] = fromhex([[
		FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1 29024E08 8A67CC74
		020BBEA6 3B139B22 514A0879 8E3404DD EF9519B3 CD3A431B 302B0A6D F25F1437
		4FE1356D 6D51C245 E485B576 625E7EC6 F44C42E9 A637ED6B 0BFF5CB6 F406B7ED
		EE386BFB 5A899FA5 AE9F2411 7C4B1FE6 49286651 ECE65381 FFFFFFFF FFFFFFFF
	]]),

	["RFC3526/Oakley Group 5"] = fromhex([[
		FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1 29024E08 8A67CC74
		020BBEA6 3B139B22 514A0879 8E3404DD EF9519B3 CD3A431B 302B0A6D F25F1437
		4FE1356D 6D51C245 E485B576 625E7EC6 F44C42E9 A637ED6B 0BFF5CB6 F406B7ED
		EE386BFB 5A899FA5 AE9F2411 7C4B1FE6 49286651 ECE45B3D C2007CB8 A163BF05
		98DA4836 1C55D39A 69163FA8 FD24CF5F 83655D23 DCA3AD96 1C62F356 208552BB
		9ED52907 7096966D 670C354E 4ABC9804 F1746C08 CA237327 FFFFFFFF FFFFFFFF
	]]),

	["RFC3526/Oakley Group 14"] = fromhex([[
		FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1 29024E08 8A67CC74
		020BBEA6 3B139B22 514A0879 8E3404DD EF9519B3 CD3A431B 302B0A6D F25F1437
		4FE1356D 6D51C245 E485B576 625E7EC6 F44C42E9 A637ED6B 0BFF5CB6 F406B7ED
		EE386BFB 5A899FA5 AE9F2411 7C4B1FE6 49286651 ECE45B3D C2007CB8 A163BF05
		98DA4836 1C55D39A 69163FA8 FD24CF5F 83655D23 DCA3AD96 1C62F356 208552BB
		9ED52907 7096966D 670C354E 4ABC9804 F1746C08 CA18217C 32905E46 2E36CE3B
		E39E772C 180E8603 9B2783A2 EC07A28F B5C55DF0 6F4C52C9 DE2BCBF6 95581718
		3995497C EA956AE5 15D22618 98FA0510 15728E5A 8AACAA68 FFFFFFFF FFFFFFFF
	]]),

	["RFC3526/Oakley Group 15"] = fromhex([[
		FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1 29024E08 8A67CC74
		020BBEA6 3B139B22 514A0879 8E3404DD EF9519B3 CD3A431B 302B0A6D F25F1437
		4FE1356D 6D51C245 E485B576 625E7EC6 F44C42E9 A637ED6B 0BFF5CB6 F406B7ED
		EE386BFB 5A899FA5 AE9F2411 7C4B1FE6 49286651 ECE45B3D C2007CB8 A163BF05
		98DA4836 1C55D39A 69163FA8 FD24CF5F 83655D23 DCA3AD96 1C62F356 208552BB
		9ED52907 7096966D 670C354E 4ABC9804 F1746C08 CA18217C 32905E46 2E36CE3B
		E39E772C 180E8603 9B2783A2 EC07A28F B5C55DF0 6F4C52C9 DE2BCBF6 95581718
		3995497C EA956AE5 15D22618 98FA0510 15728E5A 8AAAC42D AD33170D 04507A33
		A85521AB DF1CBA64 ECFB8504 58DBEF0A 8AEA7157 5D060C7D B3970F85 A6E1E4C7
		ABF5AE8C DB0933D7 1E8C94E0 4A25619D CEE3D226 1AD2EE6B F12FFA06 D98A0864
		D8760273 3EC86A64 521F2B18 177B200C BBE11757 7A615D6C 770988C0 BAD946E2
		08E24FA0 74E5AB31 43DB5BFC E0FD108E 4B82D120 A93AD2CA FFFFFFFF FFFFFFFF
	]]),

	["RFC3526/Oakley Group 16"] = fromhex([[
		FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1 29024E08 8A67CC74
		020BBEA6 3B139B22 514A0879 8E3404DD EF9519B3 CD3A431B 302B0A6D F25F1437
		4FE1356D 6D51C245 E485B576 625E7EC6 F44C42E9 A637ED6B 0BFF5CB6 F406B7ED
		EE386BFB 5A899FA5 AE9F2411 7C4B1FE6 49286651 ECE45B3D C2007CB8 A163BF05
		98DA4836 1C55D39A 69163FA8 FD24CF5F 83655D23 DCA3AD96 1C62F356 208552BB
		9ED52907 7096966D 670C354E 4ABC9804 F1746C08 CA18217C 32905E46 2E36CE3B
		E39E772C 180E8603 9B2783A2 EC07A28F B5C55DF0 6F4C52C9 DE2BCBF6 95581718
		3995497C EA956AE5 15D22618 98FA0510 15728E5A 8AAAC42D AD33170D 04507A33
		A85521AB DF1CBA64 ECFB8504 58DBEF0A 8AEA7157 5D060C7D B3970F85 A6E1E4C7
		ABF5AE8C DB0933D7 1E8C94E0 4A25619D CEE3D226 1AD2EE6B F12FFA06 D98A0864
		D8760273 3EC86A64 521F2B18 177B200C BBE11757 7A615D6C 770988C0 BAD946E2
		08E24FA0 74E5AB31 43DB5BFC E0FD108E 4B82D120 A9210801 1A723C12 A787E6D7
		88719A10 BDBA5B26 99C32718 6AF4E23C 1A946834 B6150BDA 2583E9CA 2AD44CE8
		DBBBC2DB 04DE8EF9 2E8EFC14 1FBECAA6 287C5947 4E6BC05D 99B2964F A090C3A2
		233BA186 515BE7ED 1F612970 CEE2D7AF B81BDD76 2170481C D0069127 D5B05AA9
		93B4EA98 8D8FDDC1 86FFB7DC 90A6C08F 4DF435C9 34063199 FFFFFFFF FFFFFFFF
	]]),

	["RFC5114/1024-bit MODP Group with 160-bit Prime Order Subgroup"] = fromhex([[
		B10B8F96 A080E01D DE92DE5E AE5D54EC 52C99FBC FB06A3C6 9A6A9DCA 52D23B61
		6073E286 75A23D18 9838EF1E 2EE652C0 13ECB4AE A9061123 24975C3C D49B83BF
		ACCBDD7D 90C4BD70 98488E9C 219A7372 4EFFD6FA E5644738 FAA31A4F F55BCCC0
		A151AF5F 0DC8B4BD 45BF37DF 365C1A65 E68CFDA7 6D4DA708 DF1FB2BC 2E4A4371
	]]),

	["RFC5114/2048-bit MODP Group with 224-bit Prime Order Subgroup"] = fromhex([[
		AD107E1E 9123A9D0 D660FAA7 9559C51F A20D64E5 683B9FD1 B54B1597 B61D0A75
		E6FA141D F95A56DB AF9A3C40 7BA1DF15 EB3D688A 309C180E 1DE6B85A 1274A0A6
		6D3F8152 AD6AC212 9037C9ED EFDA4DF8 D91E8FEF 55B7394B 7AD5B7D0 B6C12207
		C9F98D11 ED34DBF6 C6BA0B2C 8BBC27BE 6A00E0A0 B9C49708 B3BF8A31 70918836
		81286130 BC8985DB 1602E714 415D9330 278273C7 DE31EFDC 7310F712 1FD5A074
		15987D9A DC0A486D CDF93ACC 44328387 315D75E1 98C641A4 80CD86A1 B9E587E8
		BE60E69C C928B2B9 C52172E4 13042E9B 23F10B0E 16E79763 C9B53DCF 4BA80A29
		E3FB73C1 6B8E75B9 7EF363E2 FFA31F71 CF9DE538 4E71B81C 0AC4DFFE 0C10E64F
	]]),

	["RFC5114/2048-bit MODP Group with 256-bit Prime Order Subgroup"] = fromhex([[
		87A8E61D B4B6663C FFBBD19C 65195999 8CEEF608 660DD0F2 5D2CEED4 435E3B00
		E00DF8F1 D61957D4 FAF7DF45 61B2AA30 16C3D911 34096FAA 3BF4296D 830E9A7C
		209E0C64 97517ABD 5A8A9D30 6BCF67ED 91F9E672 5B4758C0 22E0B1EF 4275BF7B
		6C5BFC11 D45F9088 B941F54E B1E59BB8 BC39A0BF 12307F5C 4FDB70C5 81B23F76
		B63ACAE1 CAA6B790 2D525267 35488A0E F13C6D9A 51BFA4AB 3AD83477 96524D8E
		F6A167B5 A41825D9 67E144E5 14056425 1CCACB83 E6B486F6 B3CA3F79 71506026
		C0B857F6 89962856 DED4010A BD0BE621 C3A3960A 54E710C3 75F26375 D7014103
		A4B54330 C198AF12 6116D227 6E11715F 693877FA D7EF09CA DB094AE9 1E1A1597
	]])
}


-- Add additional context (protocol) to debug output
local function ctx_log(level, protocol, fmt, ...)
  return stdnse.debug(level, "(%s) " .. fmt, protocol, ...)
end


-- returns a function that yields a new tls record each time it is called
local function get_record_iter(sock)
  local buffer = ""
  local i = 1
  return function ()
    local record
    i, record = tls.record_read(buffer, i)
    if record == nil then
      local status, err
      status, buffer, err = tls.record_buffer(sock, buffer, i)
      if not status then
        return nil, err
      end
      i, record = tls.record_read(buffer, i)
      if record == nil then
        return nil, "done"
      end
    end
    return record
  end
end


local function get_server_response(host, port, t)
  local timeout = stdnse.get_timeout(host, 10000, 5000)

  -- Create socket.
  local status, sock, err
  local starttls = sslcert.getPrepareTLSWithoutReconnect(port)
  if starttls then
    status, sock = starttls(host, port)
    if not status then
      ctx_log(1, t.protocol, "Can't connect: %s", sock)
      return nil
    end
  else
    sock = nmap.new_socket()
    sock:set_timeout(timeout)
    status, err = sock:connect(host, port)
    if not status then
      ctx_log(1, t.protocol, "Can't connect: %s", err)
      sock:close()
      return nil
    end
  end

  sock:set_timeout(timeout)

  -- Send request.
  local req = tls.client_hello(t)
  status, err = sock:send(req)
  if not status then
    ctx_log(1, t.protocol, "Can't send: %s", err)
    sock:close()
    return nil
  end

  -- Read response.
  local get_next_record = get_record_iter(sock)
  local records = {}
  while true do
    local record
    record, err = get_next_record()
    if not record then
      ctx_log(1, t.protocol, "Couldn't read a TLS record: %s", err)
      sock:close()
      return records
    end
    -- Collect message bodies into one record per type
    records[record.type] = records[record.type] or record
    local done = false
    for j = 1, #record.body do -- no ipairs because we append below
      local b = record.body[j]
      done = ((record.type == "alert" and b.level == "fatal") or
        (record.type == "handshake" and b.type == "server_hello_done"))
      table.insert(records[record.type].body, b)
    end
    if done then
      sock:close()
      return records
    end
  end
end


local function get_dhe_params(host, port, protocol, ciphers)
	local cipher, packed
	local t = {}
	t.protocol = protocol
	t.ciphers = ciphers
	t.extensions = {}

	if host.targetname then
		t.extensions.server_name = tls.EXTENSION_HELPERS.server_name(host.targetname)
	end

	local records = get_server_response(host, port, t)

	local alert = records.alert
	if alert then
		for j = 1, #alert.body do
			ctx_log(2, protocol, "Received alert: %s", alert.body[j].description)
		end
	end

	-- Extract negotiated cipher suite and key exchange data
	local handshake = records.handshake
	if handshake then
		for j = 1, #handshake.body do
			if handshake.body[j].type == "server_hello" then
				cipher = handshake.body[j].cipher
			elseif handshake.body[j].type == "server_key_exchange" then
				packed = handshake.body[j].data
			end
		end
	end

	-- Unpack and return the DH parameters
	if cipher and packed then
		local info = tls.cipher_info(cipher)
		local data = tls.KEX_ALGORITHMS[info.kex].server_key_exchange(packed)
		return data.dhparams
	end

	return nil
end


local function get_dhe_ciphers()
	local dhe_ciphers = {}
	local dhe_exports = {}

	for cipher, _ in pairs(tls.CIPHERS) do
		local info = tls.cipher_info(cipher)
		if stdnse.contains(DHE_ALGORITHMS, info.kex) and
			not info.draft and info.hash ~= "RMD" then
			dhe_ciphers[#dhe_ciphers + 1] = cipher
		end
		if stdnse.contains(DHE_ALGORITHMS_EXPORT, info.kex) then
			dhe_exports[#dhe_exports + 1] = cipher
		end
	end

	return dhe_ciphers, dhe_exports
end


local function output_dhprime(response, dhparams, numprime)
	local dhinfo = stdnse.output_table()
	local length = #dhparams.p * 8
	local common, label = stdnse.contains(DHE_PRIMES, dhparams.p)

	if common then
		dhinfo["Source"] = label
	else
		dhinfo["Source"] = "Unknown/custom-generated"
	end

	dhinfo["Length"] = ("%d bits"):format(length)

	value = stdnse.strsplit(" ", stdnse.tohex(dhparams.p, {separator = " ", group = 64}))
	dhinfo["Value"] = value

	if length <= 512 or (common and length <= 1024) then
		response["LOGJAM"] = "Vulnerable to DH precomputation attacks!"
	end

	response[("MODP PRIME #%d"):format(numprime)] = dhinfo
end


portrule = function(host, port)
	return shortport.ssl(host, port) or sslcert.getPrepareTLSWithoutReconnect(port)
end


action = function(host, port)
	local response = stdnse.output_table()
	local dhe_ciphers, dhe_exports = get_dhe_ciphers()
	local dhparams
	local primes = {}

	for protocol, _ in pairs(tls.PROTOCOLS) do
		-- Try DHE_EXPORT ciphersuites
		dhparams = get_dhe_params(host, port, protocol, dhe_exports)
		if dhparams then
			if not stdnse.contains(primes, dhparams.p) then
				primes[#primes + 1] = dhparams.p
				output_dhprime(response, dhparams, #primes)
			end
		end

		-- Try non-export DHE ciphersuites
		dhparams = get_dhe_params(host, port, protocol, dhe_ciphers)
		if dhparams then
			if not stdnse.contains(primes, dhparams.p) then
				primes[#primes + 1] = dhparams.p
				output_dhprime(response, dhparams, #primes)
			end
		end
	end

	if #primes > 0 then
		return response
	else
		return "Ephemeral Diffie-Hellman key exchange not accepted"
	end
end
