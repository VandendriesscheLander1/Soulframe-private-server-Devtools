-- Dev library, run in the box's script VM by `python tools/devlua.py "<command>"` (findings/0031, 0032).
-- Every call comes from the game's own scripts; the a_XXXXXXXX names are engine methods we have no name for yet.
-- The command's return value (or the error) is logged to sf-bootstrap.log. devlua.py puts `local sfdev_enemies`
-- (BossFightTester's enemy list) in front of this file and `return <command>` after it.
--   spawn("MeleeGruntAgent", 3[, level])   any enemy type: a full /SF/Types/... path or the end of one (see enemies())
--   freeze() / freeze(false)              pause the AI of every agent within 50 m (freeze(true, radius)) / resume those
--   god() / god(false)                    the player can't be damaged
--   time(7.5) / time()                    set the time of day and hold it / let it run again
--   pace(10)                              let time run at 10x its normal rate (pace(1) = normal)
--   weather(clouds, wind, rain, lightning, rainbow, fade)   e.g. weather(1, 1, true, true, 0, 5) = a storm over 5 s
--   natural(fade)                         hand the weather back to the game's cycle
--   look(3000) / forward(200) / up(30)    teleport where the camera looks / ahead along it / straight up
--   place("SilentRoseEntrance") / back()  teleport to a tagged place (see `places`) / to before the last teleport
--   coords("120 35 -880")                 teleport to x y z
--   marker()                              teleport to the map marker (F10 does this too, panel open or not)
--   clear()                               remove everything spawn() made
--   enemies("Grunt")                      list matching enemy types
--   give("/SF/Weapons/...", 2[, quality]) put items in your inventory (our server's devCheats.php); quality 1..6
--   credits(10000)                        add credits
-- The chunk also returns `frame` (devlua.py: `return frame, (command)`): sf_bootstrap.dll calls it every frame while
-- the ImGui overlay is shown (F9), and it draws the SF dev panel with the game's own ImGui natives (findings/0033).

sfdev = sfdev or { spawned = {} } -- our only global (the game shares _G), so spawned agents survive reloads
local DEV_PAUSE = Symbol("DevFreeze")
local INVULNERABLE = Symbol("Invulnerable")

local function player() -- the local player's avatar (BossFightTester teleports and spawns around it)
    return gRegion:a_c4f78a8f()
end

local function npcs()
    return gRegion:GetNpcMgr():a_7d789620()
end

local function lower(s)
    return string.lower(s)
end

local function matches(text)
    local found = {}
    for _, path in ipairs(sfdev_enemies or {}) do
        if string.find(lower(path), lower(text), 1, true) then
            table.insert(found, path)
        end
    end
    return found
end

local function find(name)
    if string.sub(name, 1, 1) == "/" then
        return name
    end
    for _, path in ipairs(sfdev_enemies or {}) do
        if lower(string.sub(path, -#name - 1)) == "/" .. lower(name) then
            return path
        end
    end
    return matches(name)[1]
end

local function enemies(text)
    return table.concat(matches(text or ""), "\n")
end

-- BossFightTester's SpawnWithTestHarness: the NPC manager places the agent around the player (8 = radius).
local function spawn(name, n, level)
    local path = find(name)
    if not path then
        return "no enemy type matches " .. name
    end
    local made = 0
    for _ = 1, n or 1 do
        local agent = npcs():a_c91d5f5b(Type(path), player(), 8, EMPTY_SYMBOL, level or 1)
        if not IsNull(agent) then
            table.insert(sfdev.spawned, agent)
            made = made + 1
        end
    end
    return "spawned " .. made .. " x " .. path
end

-- GenericQuest pauses every agent near the ancestor this way during a cinematic.
local function freeze(on, radius)
    local count = 0
    if on == false then -- release exactly what we froze, wherever it is now
        for _, agent in ipairs(sfdev.frozen or {}) do
            if not IsNull(agent) then
                agent:SetPaused(false, DEV_PAUSE)
                count = count + 1
            end
        end
        sfdev.frozen = {}
        return "unfroze " .. count .. " agents"
    end
    sfdev.frozen = sfdev.frozen or {}
    for _, agent in ipairs(npcs():a_e0730826(player(), radius or 50, true)) do
        if not IsNull(agent) then
            agent:SetPaused(true, DEV_PAUSE)
            table.insert(sfdev.frozen, agent)
            count = count + 1
        end
    end
    return "froze " .. count .. " agents"
end

-- DemoConversation makes the player invulnerable during a talk with the same status call.
local function god(on)
    local status = player():a_7470861b()
    if on == false then
        status:a_63396172(INVULNERABLE)
        return "god off"
    end
    status:a_9fba31e6(INVULNERABLE, 26, 6, 0)
    return "god on"
end

-- ---- time and weather: the calls ModifySkyLib makes on a sky ----

local function skies()
    return gRegion:FindAll(a_4d4372ee)
end

local function main_sky() -- ModifySkyLib.GetActiveSky; the weather lives on it
    for _, sky in ipairs(skies()) do
        if sky:IsMain() then
            return sky
        end
    end
    return nil
end

local function clock(hour) -- 13.5 -> "13:30"
    hour = math.fmod(hour, 24)
    return string.format("%02d:%02d", math.floor(hour), math.floor(math.fmod(hour, 1) * 60))
end

local function now() -- ModifySkyLib.FadeTimeOfDay reads the time here
    return gRegion:GetLevelInfo():GetTimeOfDay()
end

-- DevImGuiTools' time menu and ModifySkyLib do this to each sky.
local function time(hour)
    local count = 0
    for _, sky in ipairs(skies()) do
        if hour then
            sky:SetTimeOfDay(math.fmod(hour, 24))
        end
        sky:SetTimeOfDayPaused(hour ~= nil)
        count = count + 1
    end
    return (hour and ("time " .. clock(hour) .. ", held") or "time running") .. " on " .. count .. " skies"
end

-- ModifySkyLib.SetTimeOfDayRate; a_3e305fe5 reads the rate (DayNight). The first rate we see is "normal".
-- ponytail: one normal rate for every sky and area; keep one per sky tag if areas ever turn out to differ.
local function pace(times)
    local count = 0
    for _, sky in ipairs(skies()) do
        sfdev.rate = sfdev.rate or sky:a_3e305fe5()
        sky:SetTimeOfDayRate(sfdev.rate * times)
        sky:SetTimeOfDayPaused(false)
        count = count + 1
    end
    return "time running at x" .. times .. " on " .. count .. " skies"
end

-- Amounts 0..1, rainbow 0 none / 1 / 2 double, fade in seconds. The weather cycle goes off first, as in
-- ModifySkyLib.ClearWeatherAndDisableCycle, so it doesn't roll its own weather over ours.
local function weather(clouds, wind, rain, lightning, rainbow, fade)
    local sky = main_sky()
    if not sky then
        return "no main sky here"
    end
    fade = fade or 0
    rainbow = rainbow or 0
    sky:SetWeatherCycleEnabled(false)
    sky:SetOvercast(clouds, fade)
    sky:SetWindy(wind, fade)
    sky:SetRaining(rain == true, fade)
    sky:SetLightning(lightning == true, 0, true) -- as SetStorming / ClearWeather call it
    sky:SetRainbow(rainbow > 0, rainbow > 1, rainbow > 0 and 1 or 0, fade)
    return "weather set (natural cycle off)"
end

local function natural(fade)
    local sky = main_sky()
    if not sky then
        return "no main sky here"
    end
    sky:SetWeatherCycleEnabled(true, fade or 0)
    return "natural weather cycle on"
end

local function percent(n)
    return math.floor(n * 100 + 0.5) .. "%"
end

local function sky_now()
    local sky = main_sky()
    local text = clock(now())
    if not sky then
        return text .. "   (no main sky)"
    end
    local wet = {}
    if sky:IsRaining() then table.insert(wet, "rain") end
    if sky:IsLightning() then table.insert(wet, "lightning") end
    if sky:IsDoubleRainbow() then table.insert(wet, "double rainbow") elseif sky:IsRainbow() then table.insert(wet, "rainbow") end
    return text .. "   clouds " .. percent(sky:GetOvercastAmount()) .. "   wind " .. percent(sky:GetWindAmount())
        .. (#wet > 0 and ("   " .. table.concat(wet, ", ")) or "")
        .. (sky:IsWeatherCycleEnabled() and "   (natural cycle)" or "   (cycle off)")
end

-- ---- teleport ----

-- Real atoms for two globals whose names in engine_atoms.json are guesses that don't hash to them (box run
-- 2026-10-30: `RotationToDirection` compiled to a string global and was nil). tools/devlua.py now refuses such globals.
local RotationToDirection = a_e97f3142
local ZeroVector = a_28d5d4aa

local function go(pos, what)
    local me = player()
    sfdev.back = me:GetPosition()
    me:Teleport(pos, me:GetRotation())
    return "teleported: " .. what
end

local function back()
    if not sfdev.back then
        return "no teleport to go back from yet"
    end
    return go(sfdev.back, "back")
end

-- RaycastLib.GetGroundPos: an untouched out vector means nothing was hit.
local function ray(from, to)
    local hit = Vector()
    gRegion:Raycast(from, to, player(), nil, hit, true)
    if hit == ZeroVector then
        return nil
    end
    return hit
end

-- OdeShock aims the same way: view position plus the camera direction.
local function look(range)
    local me = player()
    local from = me:CameraControl():GetViewPosition()
    local hit = ray(from, from + RotationToDirection(me:GetCameraView()) * range)
    if not hit then
        return "nothing within " .. range .. " m where the camera looks"
    end
    return go(hit + Vector(0, 1, 0), math.floor(Distance(from, hit)) .. " m to where the camera looks")
end

local function forward(dist)
    local me = player()
    local to = me:GetPosition() + RotationToDirection(me:GetCameraView()) * dist
    local ground = ray(to + Vector(0, 500, 0), to - Vector(0, 500, 0))
    if not ground then
        return go(to, dist .. " m ahead (no ground found, in the air)")
    end
    return go(ground + Vector(0, 1, 0), dist .. " m ahead")
end

local function up(height)
    return go(player():GetPosition() + Vector(0, height, 0), height .. " m up")
end

local function coords(text)
    local n = {}
    for v in string.gmatch(text, "%-?%d+%.?%d*") do
        table.insert(n, tonumber(v))
    end
    if #n ~= 3 then
        return "type three numbers: x y z"
    end
    return go(Vector(n[1], n[2], n[3]), text)
end

local function here()
    local p = player():GetPosition()
    return string.format("%.1f %.1f %.1f", p.x, p.y, p.z)
end

-- The map marker comes from sf_bootstrap.dll (scripts can only set it), as x and z: the height comes from a raycast.
-- Terrain that far off may not be streamed in yet, so then we hover above the marker until the ground shows up.
local function marker()
    local m = sfdev.marker
    if not m then
        return "no map marker: place one on the map first"
    end
    local spot = Vector(m[1], player():GetPosition().y, m[2])
    local ground = ray(spot + Vector(0, 2000, 0), spot - Vector(0, 2000, 0))
    if ground then
        return go(ground + Vector(0, 1, 0), "map marker")
    end
    go(spot + Vector(0, 300, 0), "map marker")
    sfdev.landing = { m[1], spot.y + 300, m[2], 0 }
    return "above the map marker, landing once the ground loads"
end

-- Every frame while hovering: hold the height (no fall), land when the ground shows up, give up after ~10 s.
local function land()
    local l = sfdev.landing
    l[4] = l[4] + 1
    local spot = Vector(l[1], l[2], l[3])
    local ground = ray(spot + Vector(0, 2000, 0), spot - Vector(0, 3000, 0))
    local me = player()
    if ground then
        sfdev.landing = nil
        me:Teleport(ground + Vector(0, 1, 0), me:GetRotation())
        return "teleported: map marker"
    end
    if l[4] > 600 then
        sfdev.landing = nil
        return "no ground under the map marker after 10 s; you're above it"
    end
    me:Teleport(spot, me:GetRotation())
    return nil
end

-- DevImGuiTools' teleport list (its menu body is compiled out of retail) and the tags the map's fast travel uses
-- (Map.lua Teleport). A tag only resolves in the area it's placed in.
local places = {
    { "Nearest job board tree (fast travel)", "MapTreeJobBoard" },
    { "Silent Rose entrance", "SilentRoseEntrance" },
    { "Alca's Children entrance", "AlcasChildrenEntrance" },
    { "Kith of Kings entrance", "KithOfKingsEntrance" },
    { "Kith of Kings (outside)", "KithOfKingsOutsideEntrance" },
    { "Sprout cave", "SproutCaveLocation" },
    { "Wishing well", "WishingWellLocation" },
    { "Ancestor: Tuvalkane", "AwakenTuvalkane" },
    { "Ancestor: Verminia", "AwakenVerminia" },
    { "Above-world view test", "AboveWorldViewTest" },
}

-- DevImGuiTools lands next to a target on the navmesh (radius 100), not inside it.
local function place(tag)
    local target = gRegion:FindNearestTagged(Symbol(tag), player():GetPosition())
    if IsNull(target) then
        return tag .. " isn't in this area"
    end
    local pos = npcs():a_0e0a6fee(target:GetPosition() + Vector(3, 0, 0), 100, 100)
    if pos == nil or pos == ZeroVector then
        pos = target:GetPosition() + Vector(0, 1, 0)
    end
    return go(pos, tag)
end

local function clear()
    local count = 0
    for _, agent in ipairs(sfdev.spawned) do
        if not IsNull(agent) then
            local avatar = agent:GetAvatar()
            if not IsNull(avatar) then
                avatar:Destroy()
                count = count + 1
            end
        end
    end
    sfdev.spawned = {}
    return "removed " .. count
end

-- ---- items: our server's devCheats.php (tools/admin.py dev_cheats, the devs' own cheat endpoint), then an inventory
-- sync, so the item is there without logging in again ----

-- Engine.WebGet, as Background.lua fetches getGuildDojo.php. DevImGuiTools' Engine.a_16a40eb5 sent nothing in retail
-- (box run 2026-10-30 18:16: no request reached the server). WebGet's callback is a function name, which our chunk
-- can't define, so frame() syncs the inventory SYNC_FRAMES after asking instead.
-- ponytail: a fixed wait, not the answer; the local server answers in milliseconds.
local SYNC_FRAMES = 30

local function cheat(query, done)
    local url = a_c67f9605:a_2863bfee() .. "devCheats.php?" .. a_a0f6588f:GetPlayerProfile(0):GetCredentials() .. query
    Engine.WebGet(url, "")
    sfdev.sync = { SYNC_FRAMES, done }
    return "asking the server..."
end

-- Every frame while a cheat is pending: count down, then re-read the inventory as Background.lua does.
local function sync()
    local s = sfdev.sync
    s[1] = s[1] - 1
    if s[1] > 0 then
        return nil
    end
    sfdev.sync = nil
    gGameData:SyncInventoryFromDB("", true)
    return s[2]
end

local qualities = { "Worn", "Military", "Officer", "Noble", "Masterwork", "Legendary" }

local function give(path, n, quality)
    n = n or 1
    return cheat("&AddItem=" .. path .. "&Count=" .. n .. "&Quality=IQ_" .. string.upper(qualities[quality or 6]),
        "got " .. n .. " x " .. string.match(path, "[^/]+$"))
end

local function credits(n)
    return cheat("&Credits=" .. n, "got " .. n .. " credits")
end

-- ---- SF dev panel (in game, F9) ----

-- Our own tables never use a field name that compiles to an atom (any `a_XXXXXXXX`, or a name the game's scripts use
-- as one, e.g. `level`, `name`): the VM reads a table field's constant as a string, and an atom there crashed the game
-- (box run 2026-10-30 13:19, findings/0033). tools/devlua.py refuses such fields.
local ui = sfdev.ui or { enemy = 1, count = 1, lvl = 1, hour = 12, menus = {}, said = "" }
sfdev.ui = ui
sfdev.spots = sfdev.spots or {} -- { label, position }, kept across reloads, not across game restarts
ui.fade = ui.fade or 3
ui.overcast, ui.wind, ui.rainbow = ui.overcast or 0, ui.wind or 0, ui.rainbow or 1
ui.dist, ui.place, ui.spot = ui.dist or 100, ui.place or 1, ui.spot or 1
ui.spotname, ui.coords = ui.spotname or "spot", ui.coords or ""
ui.invlist, ui.invfilter, ui.invpick, ui.invqty, ui.invqual = ui.invlist or 1, ui.invfilter or "", ui.invpick or 1, ui.invqty or 1, ui.invqual or 6
ui.invpath, ui.invkey = ui.invpath or "", nil -- invkey nil: recompute the shown list after a reload

local times = { { "Dawn", 5.5 }, { "Morning", 8 }, { "Midday", 12 }, { "Afternoon", 15.5 },
                { "Evening", 18.5 }, { "Dusk", 20 }, { "Night", 22.5 }, { "Midnight", 0 } }
local paces = { 1, 10, 60, 360 }
-- name, clouds, wind, rain, lightning, rainbow (0 none, 1, 2 double)
local weathers = {
    { "Clear", 0, 0, false, false, 0 },
    { "Cloudy", 0.7, 0.3, false, false, 0 },
    { "Overcast", 1, 0.2, false, false, 0 },
    { "Windy", 0.4, 1, false, false, 0 },
    { "Rain", 1, 0.5, true, false, 0 },
    { "Storm", 1, 1, true, true, 0 }, -- ModifySkyLib.SetStorming
    { "Rainbow", 0.2, 0.1, false, false, 1 },
    { "Double rainbow", 0.2, 0.1, false, false, 2 },
}
local place_names = {}
for i, p in ipairs(places) do
    place_names[i] = p[1]
end
local names = {}
for i, path in ipairs(sfdev_enemies or {}) do
    names[i] = string.match(path, "[^/]+$")
end

-- The devs' menus that still have a body in retail (the other DevImGuiTools menus are compiled out). They are globals
-- of their own script, which `require` hands back. Those names must stay literal (the game keys its globals by them).
-- { title, opens its own window (else it only calls ImGuiEnd and the caller opens one), getter }
local menus = {
    { "Enemy Testing Menu", true, function() return require("SF.Scripts.Bosses.BossFightTester").AiTestMenu end },
    { "Player", false, function() return require("SF.Scripts.DevImGuiTools").TogglePlayerMenu end },
}

local function act(f, ...)
    local ok, result = pcall(f, ...)
    ui.said = ok and tostring(result) or ("error: " .. tostring(result))
end

local function menu(i, m)
    local title, own, get = m[1], m[2], m[3]
    local ok, f = pcall(get)
    if not ok or type(f) ~= "function" then
        ui.menus[i] = false
        ui.said = title .. " not reachable: " .. tostring(f)
        return
    end
    if not own then
        local _, open = ImGuiBegin(title, true)
        if not open then
            ui.menus[i] = false
        end
    end
    -- The menus expect the editor object; with nil only their "Go to Type" button fails (caught here).
    local ran, result = pcall(f, nil)
    if not ran then
        ui.menus[i] = false
        ui.said = title .. ": " .. tostring(result)
    elseif own and result == false then
        ui.menus[i] = false -- AiTestMenu returns whether its window is still open
    end
end

-- What a read-only line shows when the game can't answer right now (loading, no avatar): the panel keeps drawing.
local function safe(f)
    local ok, result = pcall(f)
    return ok and tostring(result) or "?"
end

-- `count` buttons per row
local function row(i, count)
    if (i - 1) % count ~= 0 then
        ImGuiSameLine()
    end
end

local function world_tab()
    ImGuiTextWrapped(safe(sky_now))
    ImGuiSeparatorText("Time of day (sets and holds)")
    for i, t in ipairs(times) do
        row(i, 4)
        if ImGuiButton(t[1]) then
            ui.hour = t[2]
            act(time, t[2])
        end
    end
    local hour = ImGuiSliderFloat("##hour", ui.hour, 0, 24)
    if hour ~= ui.hour then -- live while dragging
        ui.hour = hour
        act(time, hour)
    end
    ImGuiSameLine()
    ImGuiText(clock(ui.hour))
    if ImGuiButton("Hold now") then
        act(function() return time(now()) end)
    end
    for i, n in ipairs(paces) do
        ImGuiSameLine()
        if ImGuiButton((i == 1 and "Run x" or "x") .. n) then
            act(pace, n)
        end
    end
    ImGuiSeparatorText("Weather")
    ui.fade = ImGuiSliderInt("fade in (s)", ui.fade, 0, 30)
    for i, w in ipairs(weathers) do
        row(i, 4)
        if ImGuiButton(w[1]) then
            ui.overcast, ui.wind, ui.rain, ui.lightning, ui.rainbow = w[2], w[3], w[4], w[5], w[6] + 1
            act(weather, w[2], w[3], w[4], w[5], w[6], ui.fade)
        end
    end
    if ImGuiButton("Back to the natural weather cycle") then
        act(natural, ui.fade)
    end
    if ImGuiCollapsingHeader("Mix your own") then
        ui.overcast = ImGuiSliderFloat("clouds", ui.overcast, 0, 1)
        ui.wind = ImGuiSliderFloat("wind", ui.wind, 0, 1)
        local _, rain = ImGuiCheckbox("rain", ui.rain or false)
        ui.rain = rain
        ImGuiSameLine()
        local _, lightning = ImGuiCheckbox("lightning", ui.lightning or false)
        ui.lightning = lightning
        ui.rainbow = ImGuiRadioButtons({ "no rainbow", "rainbow", "double" }, ui.rainbow)
        if ImGuiButton("Apply mix") then
            act(weather, ui.overcast, ui.wind, ui.rain, ui.lightning, ui.rainbow - 1, ui.fade)
        end
    end
end

local function teleport_tab()
    ImGuiText("You are at " .. safe(here))
    local m = sfdev.marker
    if ImGuiButton("Map marker (F10)") then
        act(marker)
    end
    ImGuiSameLine()
    ImGuiText(m and string.format("x %.0f  z %.0f", m[1], m[2]) or "none placed yet")
    ImGuiTextWrapped("Aim the camera first, then F9: the camera stays put while the panel is open.")
    if ImGuiButton("Where the camera looks") then
        act(look, 3000)
    end
    ImGuiSameLine()
    if ImGuiButton("Up 30 m") then
        act(up, 30)
    end
    ImGuiSameLine()
    if ImGuiButton("Back") then
        act(back)
    end
    ui.dist = ImGuiSliderInt("##dist", ui.dist, 10, 2000)
    ImGuiSameLine()
    if ImGuiButton("Ahead (m)") then
        act(forward, ui.dist)
    end
    ImGuiSeparatorText("Places in this area")
    ui.place = ImGuiCombo("##place", ui.place, place_names)
    ImGuiSameLine()
    if ImGuiButton("Go##place") then
        act(place, places[ui.place][2])
    end
    ImGuiSeparatorText("Saved spots (until the game closes)")
    ui.spotname = ImGuiInputText("##spotname", ui.spotname)
    ImGuiSameLine()
    if ImGuiButton("Save here") then
        act(function()
            table.insert(sfdev.spots, { ui.spotname, player():GetPosition() })
            ui.spot = #sfdev.spots
            return "saved " .. ui.spotname .. " at " .. here()
        end)
    end
    if #sfdev.spots > 0 then
        local spot_names = {}
        for i, s in ipairs(sfdev.spots) do
            spot_names[i] = s[1]
        end
        ui.spot = math.min(ui.spot, #sfdev.spots)
        ui.spot = ImGuiCombo("##spot", ui.spot, spot_names)
        ImGuiSameLine()
        if ImGuiButton("Go##spot") then
            act(go, sfdev.spots[ui.spot][2], sfdev.spots[ui.spot][1])
        end
        ImGuiSameLine()
        if ImGuiButton("Forget") then
            table.remove(sfdev.spots, ui.spot)
            ui.spot = 1
        end
    end
    ImGuiSeparatorText("Coordinates (x y z)")
    ui.coords = ImGuiInputText("##coords", ui.coords)
    ImGuiSameLine()
    if ImGuiButton("Go##coords") then
        act(coords, ui.coords)
    end
    ImGuiSameLine()
    if ImGuiButton("Mine") then
        ui.coords = safe(here)
    end
end

local function spawn_tab()
    ui.enemy = ImGuiCombo("##enemy", ui.enemy, names)
    ui.count = ImGuiSliderInt("count", ui.count, 1, 20)
    ui.lvl = ImGuiSliderInt("level", ui.lvl, 1, 60)
    if ImGuiButton("Spawn") then
        act(spawn, (sfdev_enemies or {})[ui.enemy] or "MeleeGruntAgent", ui.count, ui.lvl)
    end
    ImGuiSameLine()
    if ImGuiButton("Remove spawned") then
        act(clear)
    end
    ImGuiSeparatorText("AI and player")
    if ImGuiButton("Freeze AI (50 m)") then
        act(freeze)
    end
    ImGuiSameLine()
    if ImGuiButton("Unfreeze") then
        act(freeze, false)
    end
    if ImGuiButton("God on") then
        act(god)
    end
    ImGuiSameLine()
    if ImGuiButton("God off") then
        act(god, false)
    end
    ImGuiSeparatorText("The devs' own menus")
    for i, m in ipairs(menus) do
        local changed, on = ImGuiCheckbox(m[1], ui.menus[i] or false)
        if changed then
            ui.menus[i] = on
        end
    end
end

local item_lists = {}
for i, l in ipairs(sfdev_items or {}) do
    item_lists[i] = l[1]
end

-- The chosen list narrowed by the filter, recomputed only when either changes.
local function shown_items()
    local key = ui.invlist .. "|" .. ui.invfilter
    if ui.invkey == key then
        return
    end
    ui.invkey, ui.invshown, ui.invnames, ui.invpick = key, {}, {}, 1
    for _, path in ipairs(sfdev_items[ui.invlist][2]) do
        local short = string.match(path, "[^/]+$")
        if ui.invfilter == "" or string.find(lower(short), lower(ui.invfilter), 1, true) then
            table.insert(ui.invshown, path)
            table.insert(ui.invnames, short)
        end
    end
end

local function items_tab()
    if not sfdev_items then
        ImGuiTextWrapped("No item lists: run tools/devlua.py again.")
        return
    end
    ui.invlist = ImGuiCombo("##list", ui.invlist, item_lists)
    ui.invfilter = ImGuiInputText("filter", ui.invfilter)
    shown_items()
    if #ui.invshown == 0 then
        ImGuiText("nothing matches")
    else
        ui.invpick = ImGuiCombo("##item", math.min(ui.invpick, #ui.invshown), ui.invnames)
    end
    ui.invqty = ImGuiSliderInt("how many", ui.invqty, 1, 100)
    ui.invqual = ImGuiCombo("weapon quality", ui.invqual, qualities)
    if ImGuiButton("Give") and #ui.invshown > 0 then
        act(give, ui.invshown[ui.invpick], ui.invqty, ui.invqual)
    end
    ImGuiSeparatorText("Any item path")
    ui.invpath = ImGuiInputText("##path", ui.invpath)
    ImGuiSameLine()
    if ImGuiButton("Give##path") then
        act(give, ui.invpath, ui.invqty, ui.invqual)
    end
    ImGuiSeparatorText("Credits")
    for i, n in ipairs({ 1000, 10000, 100000 }) do
        row(i, 3)
        if ImGuiButton("+" .. n) then
            act(credits, n)
        end
    end
    ImGuiTextWrapped("From this PC's server; the game re-reads your inventory, no relog needed.")
end

local function panel()
    if ImGuiBegin("SF dev") then
        if ImGuiBeginTabBar("tabs") then
            if ImGuiBeginTabItem("World") then
                world_tab()
                ImGuiEndTabItem()
            end
            if ImGuiBeginTabItem("Teleport") then
                teleport_tab()
                ImGuiEndTabItem()
            end
            if ImGuiBeginTabItem("Spawn & AI") then
                spawn_tab()
                ImGuiEndTabItem()
            end
            if ImGuiBeginTabItem("Items") then
                items_tab()
                ImGuiEndTabItem()
            end
            ImGuiEndTabBar()
        end
        ImGuiSeparatorText("")
        ImGuiTextWrapped(ui.said)
    end
    ImGuiEnd()
end

-- devlua.py runs its command through this, so an error is the logged answer instead of a failed chunk.
local function run(command)
    local ok, result = pcall(command)
    if ok then
        return result
    end
    return "error: " .. tostring(result)
end

-- sf_bootstrap.dll calls this every frame while the overlay is up, and while it returns true (landing at the marker,
-- a pending item sync).
-- to_marker: F10 was pressed. mx, mz: the map marker, if one is placed.
local function frame(to_marker, mx, mz)
    sfdev.marker = mx and { mx, mz } or nil
    if to_marker then
        act(marker)
    end
    if sfdev.landing then
        local ok, said = pcall(land)
        if not ok then
            sfdev.landing = nil
            said = "error: " .. tostring(said)
        end
        ui.said = said or ui.said
    end
    if sfdev.sync then
        local ok, said = pcall(sync)
        if not ok then
            sfdev.sync = nil
            said = "error: " .. tostring(said)
        end
        ui.said = said or ui.said
    end
    panel()
    for i, m in ipairs(menus) do
        if ui.menus[i] then
            menu(i, m)
        end
    end
    return sfdev.landing ~= nil or sfdev.sync ~= nil
end
