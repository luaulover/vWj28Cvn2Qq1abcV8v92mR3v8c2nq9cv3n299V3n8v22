-- Antares Executor: Key-gated + Main UI + FastFlag Injector (Mobile + PC compatible)

local HttpService = game:GetService("HttpService")
local Players = game:GetService("Players")
local TweenService = game:GetService("TweenService")
local UserInputService = game:GetService("UserInputService")
local RunService = game:GetService("RunService")

local player = Players.LocalPlayer
local playerGui = player:WaitForChild("PlayerGui")

if playerGui:FindFirstChild("AntaresLauncher") then return end

-- ===== INSTANCE CREATOR =====
local function new(class, props)
    local inst = Instance.new(class)
    for k,v in pairs(props or {}) do
        if k == "Parent" then inst.Parent = v else inst[k] = v end
    end
    return inst
end

-- ===== KEY UI =====
local keyGui = new("ScreenGui",{Parent=playerGui, Name="AntaresKeyUI"})
keyGui.IgnoreGuiInset = true

local keyFrame = new("Frame",{Parent=keyGui, Size=UDim2.fromOffset(300,150), Position=UDim2.new(0.5,-150,0.5,-75), BackgroundColor3=Color3.fromRGB(0,0,0)})
new("UICorner",{Parent=keyFrame, CornerRadius=UDim.new(0,14)})
new("UIStroke",{Parent=keyFrame, Color=Color3.fromRGB(0,100,255), Thickness=2, Transparency=0.7})

local keyLabel = new("TextLabel",{Parent=keyFrame, Size=UDim2.new(1,0,0,40), Position=UDim2.new(0,0,0,10), BackgroundTransparency=1, Text="Enter Key", TextColor3=Color3.fromRGB(255,255,255), Font=Enum.Font.GothamBold, TextSize=20})
local keyBox = new("TextBox",{Parent=keyFrame, Size=UDim2.new(1,-20,0,40), Position=UDim2.new(0,10,0,60), BackgroundColor3=Color3.fromRGB(20,20,20), TextColor3=Color3.fromRGB(255,255,255), Font=Enum.Font.Gotham, TextSize=18, PlaceholderText="Paste your key here"})
new("UICorner",{Parent=keyBox, CornerRadius=UDim.new(0,8)})

local keyBtn = new("TextButton",{Parent=keyFrame, Size=UDim2.new(0,100,0,30), Position=UDim2.new(0.5,-50,1,-40), BackgroundColor3=Color3.fromRGB(0,0,0), Text="Submit", TextColor3=Color3.fromRGB(255,255,255), Font=Enum.Font.GothamBold, TextSize=16})
new("UICorner",{Parent=keyBtn, CornerRadius=UDim.new(0,6)})

keyBtn.MouseEnter:Connect(function() TweenService:Create(keyBtn,TweenInfo.new(0.2),{BackgroundColor3=Color3.fromRGB(255,140,0)}):Play() end)
keyBtn.MouseLeave:Connect(function() TweenService:Create(keyBtn,TweenInfo.new(0.2),{BackgroundColor3=Color3.fromRGB(0,0,0)}):Play() end)

-- ===== OLD KEY SYSTEM =====
local SERVER_URL = "https://antares-awnn.onrender.com"

local function getSession()
    local req = syn and syn.request or http_request or request
    local res = req({
        Url = SERVER_URL.."/session",
        Method = "POST",
        Headers = {["Content-Type"]="application/json"}
    })
    return HttpService:JSONDecode(res.Body).session
end

local function redeemKey(session,key)
    local req = syn and syn.request or http_request or request
    local res = req({
        Url = SERVER_URL.."/redeem",
        Method = "POST",
        Headers = {["Content-Type"]="application/json"},
        Body = HttpService:JSONEncode({session=session,key=key,playerId=player.UserId})
    })
    return HttpService:JSONDecode(res.Body).success
end

-- ===== MAIN UI =====
local function createMainUI()
    local uiWidth, uiHeight = 400,420

    local gui = new("ScreenGui",{Parent=playerGui, Name="AntaresLauncher"})
    gui.IgnoreGuiInset = true

    -- Floating Icon
    local iconSize = 40
    local icon = new("TextButton",{Parent=gui, Size=UDim2.fromOffset(iconSize,iconSize), Position=UDim2.new(0.1,0,0.3,0), BackgroundColor3=Color3.fromRGB(0,0,0), Text="A", TextColor3=Color3.fromRGB(255,255,255), Font=Enum.Font.GothamBold, TextScaled=true, BorderSizePixel=0, AutoButtonColor=false})
    new("UICorner",{Parent=icon, CornerRadius=UDim.new(0,iconSize/2)})
    new("UIStroke",{Parent=icon, Color=Color3.fromRGB(50,150,255), Thickness=2, Transparency=0.5})

    -- Icon draggable (PC + mobile)
    do
        local dragging, dragStart, startPos=false,nil,nil
        icon.InputBegan:Connect(function(input)
            if input.UserInputType==Enum.UserInputType.MouseButton1 or input.UserInputType==Enum.UserInputType.Touch then
                dragging=true
                dragStart=input.Position
                startPos=icon.Position
                input.Changed:Connect(function()
                    if input.UserInputState==Enum.UserInputState.End then dragging=false end
                end)
            end
        end)
        local function updateDrag(input)
            if dragging and (input.UserInputType==Enum.UserInputType.MouseMovement or input.UserInputType==Enum.UserInputType.Touch) then
                local delta=input.Position-dragStart
                icon.Position=UDim2.new(startPos.X.Scale,startPos.X.Offset+delta.X,startPos.Y.Scale,startPos.Y.Offset+delta.Y)
            end
        end
        icon.InputChanged:Connect(updateDrag)
        UserInputService.InputChanged:Connect(updateDrag)
        UserInputService.TouchMoved:Connect(updateDrag)
    end

    -- Main UI Frame
    local mainUI = new("Frame",{Parent=gui, Size=UDim2.fromOffset(uiWidth,uiHeight), Position=UDim2.new(0.5,-uiWidth/2,0.5,-uiHeight/2), BackgroundColor3=Color3.fromRGB(0,0,0), BorderSizePixel=0, Visible=false})
    new("UICorner",{Parent=mainUI, CornerRadius=UDim.new(0,14)})
    local mainUIStroke = new("UIStroke",{Parent=mainUI, Color=Color3.fromRGB(0,100,255), Thickness=2, Transparency=0.7})
    RunService.RenderStepped:Connect(function() mainUIStroke.Transparency=0.6+0.2*math.sin(tick()*3) end)

    -- Title Bar
    local titleBar = new("Frame",{Parent=mainUI, Size=UDim2.new(1,0,0,40), BackgroundColor3=Color3.fromRGB(15,15,15)})
    new("UICorner",{Parent=titleBar, CornerRadius=UDim.new(0,14)})
    local title = new("TextLabel",{Parent=titleBar, Size=UDim2.new(1,0,1,0), BackgroundTransparency=1, Text="ANTARES", TextColor3=Color3.fromRGB(240,240,240), Font=Enum.Font.GothamBold, TextSize=16})
    local closeBtn = new("TextButton",{Parent=titleBar, Size=UDim2.new(0,28,0,28), Position=UDim2.new(1,-32,0,6), BackgroundColor3=Color3.fromRGB(15,15,15), Text="✕", TextColor3=Color3.fromRGB(220,80,80), Font=Enum.Font.GothamBold, TextSize=16})
    new("UICorner",{Parent=closeBtn, CornerRadius=UDim.new(0,6)})

    -- Make Main UI draggable (PC + mobile)
    do
        local dragging, dragStart, startPos=false,nil,nil
        local function startDrag(input)
            if input.UserInputType == Enum.UserInputType.MouseButton1 or input.UserInputType == Enum.UserInputType.Touch then
                dragging=true
                dragStart=input.Position
                startPos=mainUI.Position
                input.Changed:Connect(function()
                    if input.UserInputState==Enum.UserInputState.End then dragging=false end
                end)
            end
        end
        local function updateDrag(input)
            if dragging and (input.UserInputType==Enum.UserInputType.MouseMovement or input.UserInputType==Enum.UserInputType.Touch) then
                local delta=input.Position-dragStart
                mainUI.Position=UDim2.new(startPos.X.Scale,startPos.X.Offset+delta.X,startPos.Y.Scale,startPos.Y.Offset+delta.Y)
            end
        end
        titleBar.InputBegan:Connect(startDrag)
        titleBar.InputChanged:Connect(updateDrag)
        UserInputService.InputChanged:Connect(updateDrag)
        UserInputService.TouchMoved:Connect(updateDrag)
    end

    -- Content & Tabs (Fastflags + Credits)
    local content = new("Frame",{Parent=mainUI, Position=UDim2.new(0,0,0,40), Size=UDim2.new(1,0,1,-40), BackgroundColor3=Color3.fromRGB(10,10,10)})
    new("UICorner",{Parent=content, CornerRadius=UDim.new(0,10)})
    local tabContainer = new("Frame",{Parent=content, Position=UDim2.new(0,0,0,40), Size=UDim2.new(1,0,1,-40), BackgroundTransparency=1})
    new("UICorner",{Parent=tabContainer, CornerRadius=UDim.new(0,10)})

    local tabNames = {"Fastflags","Credits"}
    local activeTab = "Fastflags"

    -- Fastflags Box
    local fastflagsBox = new("TextBox",{Parent=tabContainer, Size=UDim2.new(1,-24,1,-60), Position=UDim2.new(0,12,0,12), BackgroundColor3=Color3.fromRGB(20,20,20), TextColor3=Color3.fromRGB(230,230,230), MultiLine=true, ClearTextOnFocus=false, Font=Enum.Font.Gotham, TextSize=14, TextWrapped=true})
    new("UICorner",{Parent=fastflagsBox, CornerRadius=UDim.new(0,8)})

    local ffBtn = new("TextButton",{Parent=tabContainer, Size=UDim2.new(0,120,0,34), Position=UDim2.new(1,-130,1,-44), BackgroundColor3=Color3.fromRGB(0,0,0), Text="Inject", TextColor3=Color3.fromRGB(255,255,255), Font=Enum.Font.GothamSemibold, TextSize=16})
    new("UICorner",{Parent=ffBtn, CornerRadius=UDim.new(0,8)})

    ffBtn.MouseEnter:Connect(function() TweenService:Create(ffBtn,TweenInfo.new(0.2),{BackgroundColor3=Color3.fromRGB(255,140,0)}):Play() end)
    ffBtn.MouseLeave:Connect(function() TweenService:Create(ffBtn,TweenInfo.new(0.2),{BackgroundColor3=Color3.fromRGB(0,0,0)}):Play() end)

    ffBtn.MouseButton1Click:Connect(function()
        local fastflags = fastflagsBox.Text
        if fastflags=="" then return end
        local e
        local ok, parsed = pcall(function() return HttpService:JSONDecode("{"..fastflags.."}") end)
        if ok then e=parsed else return warn("JSON Decode Error:",parsed) end

        local function cleanName(i) return i:gsub("^DFFlag",""):gsub("^FFlag",""):gsub("^DFInt",""):gsub("^FInt",""):gsub("^DFString",""):gsub("^FString","") end
        local function getFlag(i) local f,k=pcall(function() return getfflag(i) end) return f and k or nil end
        local function setFlag(i,v) local f,m=pcall(function() return setfflag(i,v) end) return f,m end

        for n,o in pairs(e) do
            local p = cleanName(n)
            local q = getFlag(p)
            if q ~= nil then
                local f,m = setFlag(p,tostring(o))
                if not f then warn("Failed:",p,"->",o,m) end
            else warn("Invalid:",p) end
        end

        local toast = new("TextLabel",{Parent=gui, BackgroundColor3=Color3.fromRGB(30,30,30), TextColor3=Color3.fromRGB(255,255,255), Text="Fastflags injected! Please Rejoin.", Font=Enum.Font.GothamBold, TextSize=16, Size=UDim2.new(0,250,0,40), Position=UDim2.new(0.5,-125,1,-60), BackgroundTransparency=0.2})
        new("UICorner",{Parent=toast, CornerRadius=UDim.new(0,10)})
        TweenService:Create(toast,TweenInfo.new(0.3),{Position=UDim2.new(0.5,-125,1,-80)}):Play()
        delay(2,function() TweenService:Create(toast,TweenInfo.new(0.3),{Position=UDim2.new(0.5,-125,1,-60), BackgroundTransparency=1}):Play() end)
    end)

    -- Credits
    local creditsLabel = new("TextLabel",{Parent=tabContainer, Size=UDim2.new(1,-20,0,30), Position=UDim2.new(0,10,0,10), BackgroundTransparency=1, Text="Main Developer: antar.es on Discord", TextColor3=Color3.fromRGB(255,255,255), Font=Enum.Font.GothamBold, TextSize=14, Visible=false})
    local creditsLine = new("Frame",{Parent=tabContainer, Size=UDim2.new(1,-20,0,2), Position=UDim2.new(0,10,0,40), BackgroundColor3=Color3.fromRGB(255,255,255), Visible=false})
    new("UICorner",{Parent=creditsLine, CornerRadius=UDim.new(0,1)})

    -- Tab buttons + indicator
    local tabWidths = {Fastflags=400, Credits=300}
    local indicator = new("Frame",{Parent=content, Size=UDim2.new(0,60,0,2), BackgroundColor3=Color3.fromRGB(50,150,255), Position=UDim2.new(0,10,0,38)})
    new("UICorner",{Parent=indicator, CornerRadius=UDim.new(0,2)})

    for i,name in ipairs(tabNames) do
        local btn = new("TextButton",{Parent=content, Size=UDim2.new(0,80,0,28), Position=UDim2.new(0,10+((i-1)*90),0,6), BackgroundColor3=Color3.fromRGB(20,20,20), Text=name, TextColor3=Color3.fromRGB(255,255,255), Font=Enum.Font.GothamBold, TextSize=14})
        new("UICorner",{Parent=btn, CornerRadius=UDim.new(0,6)})
        btn.MouseButton1Click:Connect(function()
            if activeTab==name then return end
            activeTab=name
            if name=="Fastflags" then
                fastflagsBox.Visible=true
                ffBtn.Visible=true
                creditsLabel.Visible=false
                creditsLine.Visible=false
            else
                fastflagsBox.Visible=false
                ffBtn.Visible=false
                creditsLabel.Visible=true
                creditsLine.Visible=true
            end
            -- Slide indicator
            TweenService:Create(indicator,TweenInfo.new(0.25,Enum.EasingStyle.Sine,Enum.EasingDirection.Out),{Position=UDim2.new(0,btn.AbsolutePosition.X-content.AbsolutePosition.X,0,38)}):Play()
            -- Resize mainUI width
            local targetWidth = tabWidths[name]
            TweenService:Create(mainUI,TweenInfo.new(0.25,Enum.EasingStyle.Sine,Enum.EasingDirection.Out),{Size=UDim2.fromOffset(targetWidth,uiHeight)}):Play()
        end)
    end

    -- Open/close UI animation
    icon.MouseButton1Click:Connect(function()
        icon.Visible = false
        mainUI.Visible = true
        mainUI.Size = UDim2.fromOffset(0,0)
        mainUI.BackgroundTransparency = 1
        TweenService:Create(mainUI, TweenInfo.new(0.25), {Size=UDim2.fromOffset(uiWidth,uiHeight), BackgroundTransparency=0}):Play()
    end)

    closeBtn.MouseButton1Click:Connect(function()
        TweenService:Create(mainUI, TweenInfo.new(0.4),{Size=UDim2.fromOffset(0,0), BackgroundTransparency=1}):Play()
        delay(0.4,function() mainUI.Visible=false; icon.Visible=true end)
    end)
end

-- ===== Key validation =====
keyBtn.MouseButton1Click:Connect(function()
    local key = keyBox.Text
    if key=="" then return end
    keyLabel.Text="Verifying..."
    keyBtn.Active=false

    local success, session = pcall(getSession)
    if not success then
        keyLabel.Text="Failed to contact server!"
        keyBtn.Active=true
        return
    end

    local ok, valid = pcall(redeemKey, session, key)
    if not ok then
        keyLabel.Text="Failed to redeem key!"
        keyBtn.Active=true
        return
    end

    if valid then
        keyLabel.Text="Access granted!"
        TweenService:Create(keyFrame, TweenInfo.new(0.4), {BackgroundTransparency=1, Size=UDim2.fromOffset(0,0)}):Play()
        delay(0.4,function() keyGui.Enabled=false; createMainUI() end)
    else
        keyLabel.Text="Invalid key or already used!"
        keyBtn.Active=true
    end
end)
