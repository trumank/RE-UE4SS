--[[
    This is a mod where all BP functions available to BP mods goes.
    Only functions that don't need any information from BPModLoader goes in here.
]]

local VerboseLogging = true

local function Log(Message, AlwaysLog)
    if not VerboseLogging and not AlwaysLog then return end
    print(Message)
end

-- Explodes a string by a delimiter into a table
local function Explode(String, Delimiter)
    local ExplodedString = {}
    local Iterator = 1
    local DelimiterFrom, DelimiterTo = string.find(String, Delimiter, Iterator)

    while DelimiterTo do
        table.insert(ExplodedString, string.sub(String, Iterator, DelimiterFrom-1))
        Iterator = DelimiterTo + 1
        DelimiterFrom, DelimiterTo = string.find(String, Delimiter, Iterator)
    end
    table.insert(ExplodedString, string.sub(String, Iterator))

    return ExplodedString
end

RegisterCustomEvent("PrintToModLoader", function(ParamContext, ParamMessage)
    -- Retrieve the param value from the param container.
    local Message = ParamMessage:get()

    -- We must do type-checking here!
    -- This is to guard against mods that don't use the correct params for their custom event.
    -- There's no way to avoid it.
    if Message:type() ~= "FString" then error(string.format("PrintToModLoader Param #1 must be FString but was %s", Message:type())) end

    -- Now the 'Message' param is validated and we're safe to use it.
    local NameParts = Explode(ParamContext:get():GetClass():GetFullName(), "/");
    local ModName = NameParts[#NameParts - 1]
    Log(string.format("[%s] %s\n", ModName, Message:ToString()))
end)
