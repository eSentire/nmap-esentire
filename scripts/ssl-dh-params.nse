local nmap = require "nmap"
local shortport = require "shortport"
local sslcert = require "sslcert"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"
local tls = require "tls"

description = [[
Script to gather ephemeral DH parameters from SSL servers.
]]

categories = {"discovery", "safe"}
author = "Jacob Gajek"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"


-- Full-strength ephemeral Diffie-Hellman key exchange variants
local DHE_ALGORITHMS = {
	"DH_anon",
	"DHE_RSA",
	"DHE_DSS",
	"DHE_PSK",
	"PSK_DHE"
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
	["Apache/DHE_EXPORT"] = fromhex([[
		9FDB8B8A 004544F0 045F1737 D0BA2E0B 274CDF1A 9F588218 FB435316 A16E3741
		71FD19D8 D8F37C39 BF863FD6 0E3E3006	80A3030C 6E4C3757 D08F70E6 AA871033
	]]),

	["mod_ssl/DHE_EXPORT"] = fromhex([[
		D4BCD524 06F69B35 994B88DE 5DB89682 C8157F62 D8F33633 EE5772F1 1F05AB22
		D6B5145B 9F241E5A CC31FF09 0A4BC711 48976F76 795094E7 1E790352 9F5A824B
	]]),

	["Apache/1024-bit"] = fromhex([[
		D67DE440 CBBBDC19 36D693D3 4AFD0AD5 0C84D239 A45F520B B88174CB 98BCE951
		849F912E 639C72FB 13B4B4D7 177E16D5 5AC179BA 420B2A29 FE324A46 7A635E81
		FF590137 7BEDDCFD 33168A46 1AAD3B72 DAE88600 78045B07 A7DBCA78 74087D15
		10EA9FCC 9DDD3305 07DD62DB 88AEAA74 7DE0F4D6 E2BD68B0 E7393E0F 24218EB3
	]]),

	["nginx/1024-bit"] = fromhex([[
		BBBC2DCA D8467490 7C43FCF5 80E9CFDB D958A3F5 68B42D4B 08EED4EB 0FB3504C
		6C030276 E710800C 5CCBBAA8 922614C5 BEECA565 A5FDF1D2 87A2BC04 9BE67780
		60E91A92 A757E304 8F68B076 F7D36CC8 F29BA5DF 81DC2CA7 25ECE662 70CC9A50
		35D8CECE EF9EA027 4A63AB1E 58FAFD49 88D0F65D 146757DA 071DF045 CFE16B9B
	]]),

	["RFC2409/Oakley Group 1"] = fromhex([[
		FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1 29024E08 8A67CC74
		020BBEA6 3B139B22 514A0879 8E3404DD	EF9519B3 CD3A431B 302B0A6D F25F1437
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
		local kex = tls.cipher_info(cipher).kex
		if stdnse.contains(DHE_ALGORITHMS, kex) then
			dhe_ciphers[#dhe_ciphers + 1] = cipher
		end
		if stdnse.contains(DHE_ALGORITHMS_EXPORT, kex) then
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
	dhinfo["Value"] = stdnse.tohex(dhparams.p)

	response[("Prime #%d"):format(numprime)] = dhinfo
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
