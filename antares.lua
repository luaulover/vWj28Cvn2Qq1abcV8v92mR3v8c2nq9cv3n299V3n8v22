-- antares.lua (secure loader)
local HttpService = game:GetService("HttpService")
local Players = game:GetService("Players")

-- The key you generated via /genkey
local KEY = _G.AntaresKey or getgenv().AntaresKey
if not KEY then
    warn("No key provided! Please set _G.AntaresKey.")
    return
end

-- Your server URL
local SERVER_URL = "https://your-server.com"

-- Build fingerprint
local player = Players.LocalPlayer
local fingerprint = {
    userid = player.UserId,
    placeid = game.PlaceId,
    jobid = game.JobId,
    executor = (identifyexecutor and identifyexecutor()) or "Unknown"
}

-- Build request payload
local payload = {
    key = KEY,
    fingerprint = fingerprint
}

-- Function to verify key with server
local function verifyKey()
    local success, response = pcall(function()
        return HttpService:PostAsync(
            SERVER_URL .. "/verify",
            HttpService:JSONEncode(payload),
            Enum.HttpContentType.ApplicationJson,
            false
        )
    end)

    if not success then
        warn("Could not reach the server: " .. tostring(response))
        return false
    end

    local ok, data = pcall(HttpService.JSONDecode, HttpService, response)
    if not ok then
        warn("Invalid JSON response from server!")
        return false
    end

    -- Check server response
    if not data.valid then
        warn("Key verification failed: " .. (data.reason or "Unknown reason"))
        return false
    end

    -- Optional: check expiration timestamp
    if data.expires and os.time() * 1000 > data.expires then
        warn("Key has expired.")
        return false
    end

    -- If valid, return the main script URL
    return data.script_url
end

-- Verify the key and load the main script
local mainScriptURL = verifyKey()
if not mainScriptURL then
    warn("Access denied. Shutting down.")
    game:Shutdown()
    return
end

-- Load the main Antares script
local success, err = pcall(function()
    loadstring(game:HttpGet(mainScriptURL))()
end)

if not success then
    warn("Failed to load main script: " .. tostring(err))
end

