local nmap = require "nmap"
local shortport = require "shortport"
local sslcert = require "sslcert"
local stdnse = require "stdnse"
local string = require "string"
local tls = require "tls2"

description = [[
Script to gather ephemeral DH parameters from SSL servers.
]]

author = "Jacob Gajek <jacob.gajek@esentire.com>"

license = "Same as Nmap--See http://nmap.org/book/man-legal.html"

categories = {"discovery"}

-- Add additional context (protocol) to debug output
local function ctx_log(level, protocol, fmt, ...)
  --return stdnse.debug(level, "(%s) " .. fmt, protocol, ...)
	--print(string.format(fmt, ...))
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

  -- Use Nmap's own discovered timeout plus 5 seconds for host processing.
  -- Default to 10 seconds total.
  local timeout = ((host.times and host.times.timeout) or 5) * 1000 + 5000

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


local function get_dh_params(host, port, protocol, ciphers)
	local results = {}
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
			if alert.body[j].level == "fatal" then
				return nil
			end
		end
	end

	local handshake = records.handshake
	if handshake then
		for j = 1, #handshake.body do
			if handshake.body[j].type == "server_hello" then
				results.cipher = handshake.body[j].cipher
			elseif handshake.body[j].type == "server_key_exchange" then
				results.packed = handshake.body[j].data
			end
		end
	end

	if results.cipher and results.packed then
		local cipher_info = tls.cipher_info(results.cipher)
		local params_func = tls.KEX_ALGORITHMS[cipher_info.kex].server_key_exchange
		if params_func then
			local params = params_func(results.packed)
			if params.dhparams then
				return params.dhparams
			end
		end
	end

	return nil
end


local function get_dh_ciphers()
	local ret = {}
	for cipher, _ in pairs(tls.CIPHERS) do
		local info = tls.cipher_info(cipher)
		local algo = tls.KEX_ALGORITHMS[info.kex]
		if algo and algo.type and algo.type == "dh" then
			ret[#ret + 1] = cipher
		end
	end
	return ret
end


local function print_param(param)
	local ret = ""
	for i = 1, #param do
		ret = ret .. string.format("%02X", param:byte(i, i))
		if i % 32 == 0 then
			ret = ret .. "\n\t\t"
		elseif i % 8 == 0 then
			ret = ret .. " "
		end
  end
	return ret
end


portrule = function(host, port)
	return shortport.ssl(host, port) or sslcert.getPrepareTLSWithoutReconnect(port)
end


action = function(host, port)
	local ret = {}

	for protocol, _ in pairs(tls.PROTOCOLS) do
		ret[#ret + 1] = protocol
		for _, cipher in ipairs(get_dh_ciphers()) do
			local dhparams = get_dh_params(host, port, protocol, { cipher })
			if dhparams then
				ret[#ret + 1] = string.format("\t%s (p: %d bits, g: %d bits)", cipher, #dhparams.p * 8, #dhparams.g * 8)
				ret[#ret + 1] = string.format("\t\t%s", print_param(dhparams.p))
			end
		end
	end

	return ret
end


