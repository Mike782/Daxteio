window.lastPacketTime = 0;
window.netUpdate = 0;

function connector(ip) {
    connect('ws://' + ip);
    $('.gameinstance').click(function() {
        $(this).addClass("connected").siblings().removeClass("connected");
    });
}

function MyApp() {
    function enter() {
        return $(".nick").val(myApp.getName()), 
		nodeList[0][1] == myApp.getName() ? false : (nodeList[0][1] = myApp.getName(), 
		setLocalStorage("nick", $(".nick").val()), 
		player_profile[selected_profile].name = myApp.getName(), data(), true);
		
    }

    function fillHSBFields() {
        var v = myApp.getTeamName();
        return $(".team").val(v), tmpTeamname == v ? false : (setLocalStorage("opt_teamname", v), player_profile[selected_profile].team = v, data(), true);		
    }

    function change() {
        setLocalStorage("selected_profile", selected_profile);
        tmpTeamname = myApp.getTeamName();
        $(".nick").val(player_profile[selected_profile].name);
        $(".team").val(player_profile[selected_profile].team);
        $(".skin-url").val(player_profile[selected_profile].skinurl).trigger("change");
        if (fillHSBFields()) {
            nodeList[0][1] = myApp.getName();
            setLocalStorage("nick", myApp.getName());
        } else {
            enter();
        }	
    }
    function data() {
        setLocalStorage("player_profile", player_profile);
    }
    var lastPlayerClic = 0;
    function initAipPreroll() {
    /*__________________________________________________*
      --------------------------------------------------
      |               Using AdinPlay API               |
      --------------------------------------------------
    *__________________________________________________*/
        if (typeof aipPlayer != "undefined") {
            adplayer = new aipPlayer({
                AD_WIDTH: 1000,
                AD_HEIGHT: 500,
                AD_FULLSCREEN: true,
                AD_CENTERPLAYER: false,
                LOADING_TEXT: 'Fetching...',
                PREROLL_ELEM: document.getElementById('preroll'),
                AIP_COMPLETE: (() => {
                    lastPlayerClic = Date.now();
                    setNick(document.getElementById("nick").value);
                }),
                AIP_REMOVE: (() => {
                    // do not
                })
            });
        } else {
            // Failed to load the adslib ads are probably blocked
            // don't call the startPreRoll function.
            // it will result in an error.
        }
    }

    function getScript(src, callback) {
        var headElm = document.head || document.getElementsByTagName('head')[0];
        var script = document.createElement("script");
        var once = true;
        script.async = "async";
        script.type = "text/javascript";
        script.charset = "UTF-8";
        script.src = src;
        script.onload = script.onreadystatechange = function() {
            if (once && (!script.readyState || /loaded|complete/.test(script.readyState))) {
                once = false;
                callback();
                script.onload = script.onreadystatechange = null;
            }
        };
        headElm.appendChild(script);
    }

    this.version = "v2.0.0";
    var v = 0.97;
    var c = 1;
    var animationDelay = 120;
    var borderSize = 50;
    var nameMassScale = 0.8;
    this.getNameMassScale = function() {
        return nameMassScale;
    };
    this.getBorderSize = function() {
        return borderSize;
    };
    this.delayAnimation = function() {
        return animationDelay;
    };
    this.getCellColor = function () {
        return c;
    };
    this.getZoomSpeed = function() {
        return v;
    };
    this.getZoomLimit = function() {
        return 0.05;
    };
    this.isEnableHideFood = this.isEnableGridline = this.isEnableBorder = this.isEnableMapGrid = this.isEnableCursorLine = this.isEnableZoom = this.isStopMovement = this.isShowBallTotal = this.isShowSTE = this.isShowScroll = false;
    this.isEnableShowAllMass = true;
    this.isEnabledSquareFood = false;
    this.isEnabledSquareCell = false;
    this.isEnableSimpleDrawing = false;
    this.isEnableAutoStart = true;
    this.isEnableMouseW = false;
    this.isEnableLockZoom = this.isEnableCustomSkin = true;
    this.isEnableAttackRange = false;
    this.isEnableTeammateIndicator = true;
    this.isEnableChatpopup = false;
    this.attackRangeRadius = 655;
    this.cellColor = "";
    this.cellColorAry = "red #76FF03 blue yellow #8207ff #2196F3 ".split(" ");
    this.doubleSpace = this.quickSpace = this.autoW = false;
    this.doubleSpaceCount = this.quickSpaceCount = 0;
    this.lockZoomG;
    this.teammateIndicatorPosition = 40;
    this.teammateIndicatorSize = 50;
    this.teammateIndicatorShowSize = 200;
    this.nameMassScale = .8;
    this.teammateIndicator;
    this.specTeammate;
    this.isSpecTeammate = false;
    this.massTextSize = 0.8;
    this.isSpectating = false;
    this.isSameColorFood = true;
    this.isEnableSplitInd = this.isShowTextStrokeLine = this.isAutoHideName = this.isAutoHideMass = this.isShowFPS = this.isTransparentCell = false;
    this.isEnabledShortMass = false;
    this.isEnableOtherSkinSupport = true;
    this.isShowPacketIO = this.isEnableShareFb = this.isEnableSound = this.isHideSelfName = this.testing = false;

    this.buildSettings = function() {
        $('.settings-modal').addClass('is-active');
        $('.close-modal').click(() => $('.settings-modal').removeClass('is-active'));
    };
    this.buildInputs = function() {
        $('.inputs-modal').addClass('is-active');
        $('.close-modal').click(() => $('.inputs-modal').removeClass('is-active'));
    };
    this.buildTheme = function() {
        $('.theme-modal').addClass('is-active');
        $('.close-modal').click(() => $('.theme-modal').removeClass('is-active'));
    };
    this.buildServers = function() {
        var url = './gameservers.json?v=' + Math.floor(Math.random() * 100000) + 1;
        var load = function(response) {
            var gameslistdiv = '';
            //var stats_div = $('<p>').addClass('servers-stats has-text-grey');
            $.each(response.gameservers, function(region, modes) {
                //console.log('processing gameserver response for region ' + region);
                var regiondiv = "<ul class=\"servers-ul\">";
                $.each(modes, function(mode, instances) {
                    $.each(instances, function(id, websocket) {
                        var instancediv = "";
                        instancediv += "<li id=\"" + mode + "\" class=\"gameinstance\" onclick=\"connector('" + websocket + "');return false;\">";
                        instancediv += mode + "<span class=\"server-number has-text-info\"> #" + id + "</span>";
                        instancediv += `<span class=\"server-status-players has-text-grey is-size-7 status-${mode}\"></span>`;
                        instancediv += "</li>";
                        regiondiv += instancediv;
                    });
                });
                regiondiv += "</ul>";
                gameslistdiv += regiondiv;
            });
            $('.servers').append(gameslistdiv);
            //$('.servers-ul').append(stats_div);
            $.fn.random = function() {
                return this.eq(Math.floor(Math.random() * this.length));
            }
            $(".servers .servers-ul li").random().addClass('connected').click();
        };
        $.ajax({
            dataType: "json",
            url: url,
            success: load
        });
    };
    this.buildScrollbar = function () {
        /*$(".settings-content").mCustomScrollbar({
            theme: "minimal"
        });
        $(".inputs-content").mCustomScrollbar({
            theme: "minimal"
        });
        $(".theme-content").mCustomScrollbar({
            theme: "minimal"
        });*/
    };
    this.init = function() {
        getScript('//api.adinplay.com/player/v2/PSL/wair.io/player.min.js', initAipPreroll);
        this.buildScrollbar(); // run the scrollbar plugin
        this.buildServers();
        $('.button-hotkey-cancel').click(() => $('.close-modal').click());
        $('.button-hotkey-save').click(() => {
            saveHotkeys();
            $('.close-modal').click();
        });
        $('.button-hotkey-reset').click(() => resetDefaultHotkey());
        // Aquí
        /*$("#drawTime").on("input", function () {
            $("#max_draw_txt").text("Max Draw Time: " + $("#drawTime").val())
        });*/
        $('.play-button').click(() => {
            if (Date.now() - lastPlayerClic < 3e5 * 2) {
                setNick(document.getElementById("nick").value);
                return;
            }
            aiptag.cmd.player.push(() => {
                adplayer.startPreRoll();
            });
        });
        $('.spectate-button').click(() => spectate());
        var c = document.getElementById("canvas");
        c.getContext("2d");
        c.mozOpaque = true;
        window.setLocalStorage = function(key, value) {
            if ("string" == typeof value) {
                localStorage.setItem(key, value);
            } else {
                localStorage.setItem(key, JSON.stringify(value));
            }
        };
		
        window.getLocalStorage = function(storageKey) {
            return localStorage.getItem(storageKey);
        };
		
        if (getLocalStorage("selected_profile")) {
            selected_profile = getLocalStorage("selected_profile");
        }
		
        if (getLocalStorage("player_profile")) {
			
            player_profile = JSON.parse(getLocalStorage("player_profile"));
			
        } else {
			
            if (getLocalStorage("nick")) {
                player_profile[selected_profile].name = getLocalStorage("nick");
            }
			
            if (getLocalStorage("opt_teamname")) {
                player_profile[selected_profile].team = getLocalStorage("opt_teamname");
            }
			
            if (getLocalStorage("skin_url")) {
                player_profile[selected_profile].skinurl = getLocalStorage("skin_url");
            }
			
        }
		
        c = 0;
		// console.log("# profiles: " + player_profile.length);
        for (; c < player_profile.length; c++) {
            window.postMessage({
                action: Action.IMAGE,
                data: player_profile[c].skinurl
            }, "*");
        }
        $('body').contextmenu((e) => e.preventDefault());
        nodeList[0] = ["me", getLocalStorage("nick"), null, null, "yellow"];
        nodeList[1] = ["top1", "", null, null, "white"];
        nodeList[0][8] = Date.now();
        nodeList[1][8] = Date.now();
        chatRoom = new ChatRoom;
        chatRoom.createChatBox();
        minimap = new Minimap;
        minimap.createMap(180);
        c = document.createElement("canvas");
        var context = c.getContext("2d");
        context.beginPath();
        context.lineWidth = 30;
        context.moveTo(0, 0);
        context.lineTo(100, 0);
        context.lineTo(50, 50);
        context.closePath();
        context.strokeStyle = "white";
        context.fillStyle = "white";
        context.stroke();
        context.fill();
        this.teammateIndicator = c;
        conn = new Connection;
        conn.connect();
    };
    this.newGame = function() {
        isJoinedGame = true;
        myApp.isStopMovement = false;
        myApp.isSpectating = false;
        myApp.cellColor = "";
        myApp.newGameImpl();
        spectateMode = false;
        nodeList[1][2] = null;
        nodeList[1][3] = null;
        /*this.auth_token = window.userToken;
        var codeSegments = [8, 1, 18, this.auth_token.length + 25, 1, 8, 10, 82, this.auth_token.length + 20, 1, 10, 13, 8, 5, 18, 5, 49, 46, 52, 46, 57, 24, 0, 32, 0, 16, 2, 26, this.auth_token.length, 1];
        var i = 0;
        for (; i <= this.auth_token.length - 1; i++) {
            codeSegments.push(this.auth_token.charCodeAt(i));
        }
        var data = new DataView(new ArrayBuffer(1 + codeSegments.length));
        data.setUint8(0, 102);
        i = 0;
        for (; i < codeSegments.length; i++) {
            data.setUint8(1 + i, codeSegments[i]);
        }
        console.log(new Uint8Array(data.buffer));
        webSocket.send(data.buffer);*/
    };
    this.afterGameLogicLoaded = function() {
        myApp.setupOption();
        myApp.setupHotKey();
        myApp.restoreSetting();
        myApp.setUpHotKeyConfigPage();
        myApp.replaceTos();
        myApp.setupHints();
		setCurrentSkin(); // Para que cargue la skin
        myApp.checkVersion();
        myApp.downloadSkin();
        $("#btn_info").click(function() {
            myApp.showAnnouncement();
        });
        $("#game_info").click(function() {
            myApp.copyGameInfo();
        });
        $(".nick").change(function() {
            enter();
        });
        $(".team").change(function() {
            fillHSBFields();
        }).focus(function() {
            tmpTeamname = myApp.getTeamName();
        });
		
        //$(".skin-url").change(function() {
		$(".skin-url").change(function() {
            var nv = getLocalStorage("skin_url");
            var v = myApp.getCustomSkinUrl();
            $(".skin-url").val(v);
            if (nv != v) {
				//console.log("Entramos: v = " + v);
                nv = /^(?:(?:https?|ftp):\/\/)(?:\S+(?::\S*)?@)?(?:(?!10(?:\.\d{1,3}){3})(?!127(?:\.\d{1,3}){3})(?!169\.254(?:\.\d{1,3}){2})(?!192\.168(?:\.\d{1,3}){2})(?!172\.(?:1[6-9]|2\d|3[0-1])(?:\.\d{1,3}){2})(?:[1-9]\d?|1\d\d|2[01]\d|22[0-3])(?:\.(?:1?\d{1,2}|2[0-4]\d|25[0-5])){2}(?:\.(?:[1-9]\d?|1\d\d|2[0-4]\d|25[0-4]))|(?:(?:[a-z\u00a1-\uffff0-9]+-?)*[a-z\u00a1-\uffff0-9]+)(?:\.(?:[a-z\u00a1-\uffff0-9]+-?)*[a-z\u00a1-\uffff0-9]+)*(?:\.(?:[a-z\u00a1-\uffff]{2,})))(?::\d{2,5})?(?:\/[^\s]*)?$/i;
				
                if ("DEFAULT" == v || nv.test(v)) {
					//console.log("Valid: URL" + v);
                    setLocalStorage("skin_url", v);
                    nodeList[0][5] = v;
                    player_profile[selected_profile].skinurl = myApp.getCustomSkinUrl();
					//console.log("getCustomSkinUrl = " + player_profile[selected_profile].skinurl);
                    data();
					//console.log("customSkin[v] = " + customSkin[v]);
					myApp.changePreviewImage(player_profile[selected_profile].skinurl);
                    if (customSkin[v]) {
                        //myApp.changePreviewImage(customSkin[v].src);
                    } else {
                        skinDownloadQueue.push(v);
                    }
                } else {
                    console.log("Not valid URL");
                    $(".skin-url").val(defaultSkin);
					$(".skin").attr("src", defaultSkin);
					$(".skin-url").change();
                }
            }
        });
        $(".nav2.arrow-left").click(function() {
            selected_profile = (player_profile.length + selected_profile - 1) % player_profile.length;
            change();
			$(".skin-url").change();
        });
        $(".nav2.arrow-right").click(function() {
            selected_profile = (selected_profile + 1) % player_profile.length;
            change();
			$(".skin-url").change();
        });
        data();
    };
    this.spectate = function(buffer2) {
        conn.joinRoom(myApp.getRoom());
        if (!(buffer2 && 0 != buffer2.length)) {
            myApp.isSpectating = true;
        }
    };
    this.newGameImpl = function() {
        var e = true;
        var sectors = getCell();
        if (!(sectors && 0 != sectors.length)) {
            e = false;
        }
        if (e) {
            nodeList[0][6] = sectors[0].color;
            conn.joinRoom(myApp.getRoom());
        } else {
            setTimeout(myApp.newGameImpl, 100);
        }
    };
    this.onDead = function() {
        isJoinedGame = false;
        conn.leaveRoom(myApp.getRoom());
    };
    this.afterGameLoaded = function() {
        myApp.isSpectating = false;
        updateLBCount = -1;
        moveTo(null, null);
        myApp.specTeammate = null;
        myApp.isStopMovement = false;
        minimap.setDeadPosition(null);
        conn.joinRoom(myApp.getRoom());
    };
    this.getRoom = function() {
        return "N/A" == myApp.getCurrentPartyCode() ? myApp.getTeamName() + myApp.getCurrentIP() : myApp.getTeamName() + myApp.getCurrentPartyCode();
    };
    this.restoreSetting = function() {
        if (getLocalStorage("opt_teamname")) {
            $(".team").val(getLocalStorage("opt_teamname"));
        }
        if (getLocalStorage("nick") && "" != getLocalStorage("nick").trim()) {
            $(".nick").val(getLocalStorage("nick", myApp.getName()));
        } else {
            $(".nick").val(myApp.getName());
            setLocalStorage("nick", myApp.getName());
        }
        nodeList[0][1] = myApp.getName();
        if (getLocalStorage("opt_zoom_speed")) {
            v = getLocalStorage("opt_zoom_speed");
            $("#opt_zoom_speed").val(v);
            $("#txt_zoom_speed").text(v);
        }
        if (getLocalStorage("opt_smooth_animation")) {
            animationDelay = getLocalStorage("opt_smooth_animation");
            $("#opt_smooth_animation").val(animationDelay);
            $("#txt_smooth_animation").text(animationDelay);
        }
        if (getLocalStorage("opt_border_size")) {
            borderSize = getLocalStorage("opt_border_size");
            $('#opt_border_size').val(borderSize);
            $('#txt_border_size').text(borderSize);
        }
        if (getLocalStorage("opt_name_mass_scale")) {
            nameMassScale = getLocalStorage("opt_name_mass_scale");
            $('#opt_name_mass_scale').val(nameMassScale);
            $('#txt_name_mass_scale').text(nameMassScale);
        }
        var n = getLocalStorage("skin_url");
        if (n && "" != n || (setLocalStorage("skin_url", defaultSkin), n = defaultSkin), n && ("" != n && ($(".skin-url").val(getLocalStorage("skin_url")), nodeList[0][5] = n, customSkin[n] ? myApp.changePreviewImage(customSkin[n].src) : skinDownloadQueue.push(getLocalStorage("skin_url")))), getLocalStorage("hotkeyMapping")) {
            hotkeyMapping = JSON.parse(getLocalStorage("hotkeyMapping"));
        } else {
            var unlock;
            for (unlock in hotkeyConfig) {
                if (hotkeyConfig[unlock].defaultHotkey) {
                    if ("" != hotkeyConfig[unlock].defaultHotkey) {
                        hotkeyMapping[hotkeyConfig[unlock].defaultHotkey] = unlock;
                    }
                }
            }
            setLocalStorage("hotkeyMapping", hotkeyMapping);
        }
        if (getLocalStorage("chatCommand")) {
            chatCommand = JSON.parse(getLocalStorage("chatCommand"));
        } else {
            chatCommand = defaultHotkeyMessageSend;
            setLocalStorage("chatCommand", chatCommand);
        }
    };
    this.replaceTos = function() {
        $(".tosBox").remove();
    };
    this.setupOption = function() {
        var options = {
            opt_self_name: {
                text: "Hide my name",
                "default": true,
                handler: function(token) {
                    myApp.isHideSelfName = token;
                }
            },
            opt_name: {
                text: "Hide Names",
                handler: function(token) {
                    setNames(!token);
                }
            },
            opt_color: {
                text: "Hide blob colors",
                handler: function(token) {
                    setColors(token);
                }
            },
            opt_mass: {
                text: "Show mass",
                "default": true,
                handler: function(token) {
                    setShowMass(token);
                }
            },
            opt_stats: {
                text: "Skip stats",
                disabled: true,
                "default": true,
                handler: function(token) {
                    setSkipStats(token);
                }
            },
            opt_mapgrid: {
                text: "Grid Locations",
                "default": true,
                handler: function(token) {
                    myApp.isEnableMapGrid = token;
                }
            },
            opt_cursorline: {
                text: "Cursor Line",
                "default": true,
                handler: function(token) {
                    myApp.isEnableCursorLine = token;
                }
            },
            opt_zoom: {
                text: "Zoom",
                "default": true,
                handler: function(token) {
                    myApp.isEnableZoom = token;
                }
            },
            opt_food: {
                text: "Hide Pellets",
                handler: function(token) {
                    myApp.isEnableHideFood = token;
                }
            },
            opt_gridline: {
                text: "Gridlines",
                handler: function(token) {
                    myApp.isEnableGridline = token;
                }
            },
            opt_simple_drawing: {
                text: "No Animations",
                "default": true,
                handler: function(token) {
                    myApp.isEnableSimpleDrawing = token;
                }
            },
            opt_square_food: {
                text: "Square Food",
                handler: function(token) {
                    myApp.isEnabledSquareFood = token;
                }
            },
            opt_square_cell: {
                text: "Square Cells",
                handler: function(token) {
                    myApp.isEnabledSquareCell = token;
                }
            },
            opt_score: {
                text: "Score",
                "default": true,
                handler: function(token) {
                    myApp.isShowScroll = token;
                }
            },
            opt_ste: {
                text: "STE",
                "default": true,
                handler: function(token) {
                    myApp.isShowSTE = token;
                }
            },
            opt_ball_total: {
                text: "[n/16]",
                "default": true,
                handler: function(token) {
                    myApp.isShowBallTotal = token;
                }
            },
            opt_minimap: {
                text: "Minimap",
                "default": true,
                handler: function(token) {
                    if (token) {
                        minimap.show();
                    } else {
                        minimap.hide();
                    }
                }
            },
            opt_mousew: {
                text: "Mouse Feed",
                handler: function(token) {
                    myApp.isEnableMouseW = token;
                }
            },
            opt_same_food_color: {
                text: "Rainbow Color",
                handler: function(token) {
                    myApp.isSameColorFood = !token;
                }
            },
            opt_transparent_cell: {
                text: "Transparent Blobs",
                handler: function(token) {
                    myApp.isTransparentCell = token;
                }
            },
            opt_fps: {
                text: "FPS",
                "default": true,
                handler: function(token) {
                    myApp.isShowFPS = token;
                }
            },
            opt_packetIO: {
                text: "Packets I/O",
                disabled: true,
                handler: function(token) {
                    myApp.isShowPacketIO = token;
                }
            },
            opt_auto_hide_mass: {
                text: "Auto Hide Mass",
                "default": true,
                handler: function(token) {
                    myApp.isAutoHideMass = token;
                }
            },
            opt_auto_hide_name: {
                text: "Auto Hide Names",
                "default": true,
                handler: function(token) {
                    myApp.isAutoHideName = token;
                }
            },
            opt_short_mass: {
                text: 'Short Mass',
                "default": true,
                handler: function(token) {
                    myApp.isEnabledShortMass = token;
                }
            },
            opt_show_text_stroke_line: {
                text: "Text Shadows",
                handler: function(token) {
                    myApp.isShowTextStrokeLine = token;
                }
            },
            opt_lock_zoom: {
                text: "Auto Zoom",
                handler: function(token) {
                    myApp.isEnableLockZoom = !token;
                }
            },
            opt_split_ind: {
                text: "Split Indicators",
                handler: function(token) {
                    myApp.isEnableSplitInd = token;
                }
            },
            opt_custom_skin: {
                text: "Custom Skins",
                "default": true,
                handler: function(token) {
                    myApp.isEnableCustomSkin = token;
                }
            },
            opt_other_skin: {
                text: "Yin Skins",
                disabled: true,
                handler: function(token) {
                    myApp.isEnableOtherSkinSupport = token;
                }
            },
            opt_chatbox: {
                text: "Chatbox",
                disabled: false,
                "default": false,
                handler: function(token) {
                    if (token) {
                        chatRoom.show();
                    } else {
                        chatRoom.hide();
                    }
                }
            },
            opt_chatpopup: {
                text: "Chat Popup",
                disabled: false,
                "default": true,
                handler: function(token) {
                    myApp.isEnableChatpopup = token;
                }
            }
        };
        window.setYinSkinSupport = function(firstRestricted) {
            options.opt_other_skin.handler(firstRestricted);
            setLocalStorage("opt_other_skin", firstRestricted);
        };
        var i;
        var row = [];
        for (i in options) {
            if (!options[i].disabled) {
                row.push('<div id="option-box"><input id="' + i + '" type="checkbox"><label id="option-text">' + options[i].text + "</label></div>");
            }
        }
        var d = row.splice(0, 13);
        var j = 0;
        for (; j < d.length; j++) {
            $(".firstSettings").append(d[j]);
        }
        j = 0;
        for (; j < row.length; j++) {
            $(".secondSettings").append(row[j]);
        }
        $("input:checkbox").change(function() {
            var firstRestricted = $(this).prop("checked");
            var type = $(this).prop("id");
            setLocalStorage(type, firstRestricted);
            if (options[type]) {
                options[type].handler(firstRestricted);
            }
        });
        for (i in options) {
            if (getLocalStorage(i)) {
                if ("true" == getLocalStorage(i)) {
                    if ("opt_other_skin" == i) {
                        setYinSkinSupport(true);
                    } else {
                        $("#" + i).click();
                    }
                }
            } else {
                if (options[i]["default"]) {
                    $("#" + i).click();
                }
            }
        }
        //$(".zoomSpeed").append('Zoom Speed: <span id="txt_zoom_speed">0.97</span></div><input oninput="$(\'#txt_zoom_speed\').text(this.value);" style="width:100%;" type="range" id="opt_zoom_speed" name="opt_zoom_speed" min="0.70" max="0.99" step="0.01" value="0.9">');
        $(".zoomSpeed").append('Zoom Speed: <span id="txt_zoom_speed">0.9</span></div><input oninput="$(\'#txt_zoom_speed\').text(this.value);" class="range-slider__range" style="width:100%;" type="range" id="opt_zoom_speed" name="opt_zoom_speed" min="0.88" max="0.99" step="0.01" value="0.9">');
        $("#opt_zoom_speed").change(function() {
            v = $("#opt_zoom_speed").val();
            setLocalStorage("opt_zoom_speed", v);
        });
        $('.nameMassScale').append('Name & Mass Size: <span id="txt_name_mass_scale">0.8</span></div><input oninput="$(\'#txt_name_mass_scale\').text(this.value);" class="range-slider__range" style="width:100%;" type="range" id="opt_name_mass_scale" name="opt_name_mass_scale" min="0.1" max="1" step="0.1" value="0.8">');
        $('#opt_name_mass_scale').change(function(event) {
            nameMassScale = $('#opt_name_mass_scale').val();
            setLocalStorage("opt_name_mass_scale", nameMassScale);
        });
        $(".delayAnimation").append('Animation Delay: <span id="txt_smooth_animation">100</span></div><input oninput="$(\'#txt_smooth_animation\').text(this.value);" class="range-slider__range" style="width:100%;" type="range" id="opt_smooth_animation" name="opt_smooth_animation" min="100" max="400" step="10" value="120">');
        $("#opt_smooth_animation").change(function() {
            animationDelay = $("#opt_smooth_animation").val();
            setLocalStorage("opt_smooth_animation", animationDelay);
        });
        $('.borderSize').append('Border Size: <span id="txt_border_size">50</span></div><input oninput="$(\'#txt_border_size\').text(this.value);" class="range-slider__range" style="width:100%;" type="range" id="opt_border_size" name="opt_border_size" min="10" max="500" step="5" value="50">');
        $('#opt_border_size').change(function() {
            borderSize = $('#opt_border_size').val();
            setLocalStorage('opt_border_size', borderSize);
        });
        /* AQUÍ */
        /*var drawTime = localStorage.getItem("max_draw_time");
        if (drawTime) {
            $("#drawTime").val(drawTime);
            document.getElementById("max_draw_txt").innerHTML = "Max Draw Time: " + drawTime;
            maxDrawTime = parseInt(drawTime);
        }
        $("#drawTime").change(function () {
            var v = $("#drawTime").val();
            v = parseInt(v);
            window.maxDrawTime = v;
            setLocalStorage("max_draw_time", v);
        }); */
        /* AQUÍ */
    };
    this.scoreInfo = function(millis) {
        if (!millis || !millis.length) {
            return "";
        }
        var optsData = "";
        return myApp.isShowSTE && (optsData += "   STE: " + this.getSTE(millis)), myApp.isShowBallTotal && (optsData += "   [" + millis.length + "/16]"), optsData;
    };
    this.scoreTxt = function(dataAndEvents) {
        return myApp.isShowScroll ? dataAndEvents : "";
    };
    this.isShowScoreInfo = function() {
        return myApp.isShowScroll || (myApp.isShowSTE || myApp.isShowBallTotal);
    };
    this.showSystemMessage = function() {
        return false;
    };
    this.getSTE = function(codeSegments) {
        var w = 0;
        var i = 0;
        for (; i < codeSegments.length; i++) {
            if (codeSegments[i]) {
                if (codeSegments[i].I) {
                    if (codeSegments[i].I.w) {
                        if (codeSegments[i].I.w > w) {
                            w = codeSegments[i].I.w;
                        }
                    }
                }
            }
        }
        return ~~(0.375 * w);
    };
    this.createGameInfoBox = function() {
        $(".gameinfo").prepend("<div id='game_info' class='agario-panel'><p id='ip_info'></p><p id='region_info'></p><p id='gamemode_info'></p><p id='party_code_info'></p><p id='lb_info'></p></div>");
        $("#game_info").append('<button id ="btn_copy_gameinfo" class="btn btn-warning btn-hotkeys" type="button">Copy</button>');
    };
    this.updateLBInfo = function() {
        var escaped = "";
        var codeSegments = myApp.getLeaderBoard();
        if (codeSegments) {
            var i = 0;
            for (; i < codeSegments.length; i++) {
                escaped += "<div>" + (i + 1) + ".  " + escapeHtml(codeSegments[i]) + "</div>";
            }
        }
        $("#lb_info").html(escaped);
    };
    this.isPrivateServer = function() {
        return PRIVATE_SERVER_IP == currentIP;
    };
    this.getCurrentIP = function() {
        return this.isPrivateServer() ? "----------" : currentIP.substring(5, currentIP.length);
    };
    this.getRegion = function() {
        return $("#region option:selected").text().split(" ")[0];
    };
    this.getGameMode = function() {
        return this.isPrivateServer() ? "----------" : $("#gamemode option:selected").text();
    };
    this.getTeamName = function() {
        return ("" == $(".team").val() ? "" : $(".team").val()).trim();
    };
    this.getCustomSkinUrl = function() {
        var ret = ($(".skin-url").val() + "").trim();
        return "" == ret ? "" : ret;
    };
    this.getCurrentPartyCode = function() {
        return $(".partyToken").val();
    };
    this.showMessage = function(message, options) {
        if (0 == $("#message_dialog").length) {
            myApp.createMessageDialog();
        }
        $("#message_dialog_title").text(message);
        $("#message_dialog_content").html(options);
        $("#message_dialog").modal({
            show: "true"
        });
    };
    this.getName = function() {
        var val = $(".nick").val().trim();
        return -1 != val.indexOf("\u200b") && (val = ""), "" == val ? "" : val;
    };
    this.getLeaderBoard = function() {
        var listenersArr = [];
        var codeSegments = getLB();
        if (codeSegments) {
            var i = 0;
            for (; i < codeSegments.length; i++) {
                listenersArr[listenersArr.length] = "" == codeSegments[i].name ? "An unnamed cell" : escapeHtml(codeSegments[i].name);
            }
        }
        return listenersArr;
    };
    this.setupHotKey = function() {
        hotkeyConfig = {
            hk_start_new_game: {
                defaultHotkey: "N",
                name: "Start new game",
                keyDown: function() {
					connect($("#chooseServer").val()); // establece el servidor al que nos conectaremos
                    setNick(myApp.getName());
                },
                type: "NORMAL"
            },
            hk_cheatw: {
                defaultHotkey: "E",
                name: "Macro W",
                keyDown: function() {
                    myApp.autoW = true;
                    handleQuickW();
                },
                keyUp: function() {
                    myApp.autoW = false;
                },
                type: "NORMAL"
            },
            hk_quick_space: {
                defaultHotkey: "T",
                name: "Quick space",
                keyDown: function() {
                    if (!myApp.quickSpace) {
                        myApp.quickSpace = true;
                        quickSpace();
                    }
                },
                keyUp: function() {
                    myApp.quickSpace = false;
                },
                type: "NORMAL"
            },
            hk_double_space: {
                defaultHotkey: "G",
                name: "Double space",
                keyDown: function() {
                    if (!myApp.doubleSpace) {
                        myApp.doubleSpace = true;
                        doubleSpace();
                    }
                },
                keyUp: function() {
                    myApp.doubleSpace = false;
                },
                type: "NORMAL"
            },
            hk_stop_movement_toggle: {
                defaultHotkey: "ALT_S",
                name: "Stop movement (Toggle)",
                keyDown: function() {
                    myApp.isStopMovement = !myApp.isStopMovement;
                    myApp.specTeammate = null;
                },
                type: "NORMAL"
            },
            hk_stop_movement: {
                defaultHotkey: "S",
                name: "Stop movement (Temporary)",
                keyDown: function() {
                    myApp.isStopMovement = true;
                    myApp.specTeammate = null;
                    moveTo(null, null);
                },
                keyUp: function() {
                    myApp.isStopMovement = false;
                },
                type: "NORMAL"
            },
            hk_split_ind: {
                defaultHotkey: "I",
                name: "On/ off split indicator",
                keyDown: function() {
                    $("#opt_split_ind").click();
                },
                type: "NORMAL"
            },
            hk_lock_zoom: {
                defaultHotkey: "L",
                name: "On/ off auto zoom",
                keyDown: function() {
                    $("#opt_lock_zoom").click();
                },
                type: "NORMAL"
            },
            hk_attack_range: {
                defaultHotkey: "A",
                name: "Show attack range (Temporary)",
                keyDown: function() {
                    myApp.isEnableAttackRange = true;
                },
                keyUp: function() {
                    myApp.isEnableAttackRange = false;
                },
                type: "NORMAL"
            },
            hk_attack_range_toggle: {
                defaultHotkey: "ALT_A",
                name: "Show attack range (Toggle)",
                keyDown: function() {
                    myApp.isEnableAttackRange = !myApp.isEnableAttackRange;
                },
                type: "NORMAL"
            },
            hk_spec_teammate: {
                defaultHotkey: "V",
                name: "Spectating teammate",
                keyDown: function() {},
                type: "NORMAL"
            },
            hk_custom_skin: {
                defaultHotkey: "",
                name: "On/ off Custom skin",
                keyDown: function() {
                    $("#opt_custom_skin").click();
                },
                type: "NORMAL"
            },
            hk_same_food_color: {
                defaultHotkey: "",
                name: "On/ off Rainbow color",
                keyDown: function() {
                    $("#opt_same_food_color").click();
                },
                type: "NORMAL"
            },
            hk_transparent_cell: {
                defaultHotkey: "",
                name: "On/ off transparent cell",
                keyDown: function() {
                    $("#opt_transparent_cell").click();
                },
                type: "NORMAL"
            },
            hk_fps: {
                defaultHotkey: "",
                name: "Show/ Hide FPS counter",
                keyDown: function() {
                    $("#opt_fps").click();
                },
                type: "NORMAL"
            },
            hk_zoom_a: {
                defaultHotkey: "1",
                name: "Zoom level 1",
                keyDown: function() {
                    if (!myApp.isEnableLockZoom) {
                        hotkeyConfig.hk_lock_zoom.keyDown();
                    }
                    setZoomLevel(0.75);
                },
                type: "NORMAL"
            },
            hk_zoom_b: {
                defaultHotkey: "2",
                name: "Zoom level 2",
                keyDown: function() {
                    if (!myApp.isEnableLockZoom) {
                        hotkeyConfig.hk_lock_zoom.keyDown();
                    }
                    setZoomLevel(0.3);
                },
                type: "NORMAL"
            },
            hk_zoom_c: {
                defaultHotkey: "3",
                name: "Zoom level 3",
                keyDown: function() {
                    if (!myApp.isEnableLockZoom) {
                        hotkeyConfig.hk_lock_zoom.keyDown();
                    }
                    setZoomLevel(0.15);
                },
                type: "NORMAL"
            },
            hk_zoom_d: {
                defaultHotkey: "4",
                name: "Zoom level 4",
                keyDown: function() {
                    if (!myApp.isEnableLockZoom) {
                        hotkeyConfig.hk_lock_zoom.keyDown();
                    }
                    setZoomLevel(0.08);
                },
                type: "NORMAL"
            },
            hk_zoom_e: {
                defaultHotkey: "5",
                name: "Zoom level 5",
                keyDown: function() {
                    if (!myApp.isEnableLockZoom) {
                        hotkeyConfig.hk_lock_zoom.keyDown();
                    }
                    setZoomLevel(0.05);
                },
                type: "NORMAL"
            },
            hk_name: {
                defaultHotkey: "ALT_N",
                name: "Show/ hide names",
                keyDown: function() {
                    $("#opt_name").click();
                },
                type: "NORMAL"
            },
            hk_self_name: {
                defaultHotkey: "",
                name: "Show/ hide own name",
                keyDown: function() {
                    $("#opt_self_name").click();
                },
                type: "NORMAL"
            },
            hk_color: {
                defaultHotkey: "",
                name: "Show/ hide colors",
                keyDown: function() {
                    $("#opt_color").click();
                },
                type: "NORMAL"
            },
            hk_mass: {
                defaultHotkey: "",
                name: "Show/ hide mass",
                keyDown: function() {
                    $("#opt_mass").click();
                },
                type: "NORMAL"
            },
            hk_zoom: {
                defaultHotkey: "ALT_Z",
                name: "On/ off Zoom",
                keyDown: function() {
                    $("#opt_zoom").click();
                },
                type: "NORMAL"
            },
            hk_food: {
                defaultHotkey: "F",
                name: "Show/ hide Pellets",
                keyDown: function() {
                    $("#opt_food").click();
                },
                type: "NORMAL"
            },
            hk_gridline: {
                defaultHotkey: "ALT_G",
                name: "Show/ hide Gridline",
                keyDown: function() {
                    $("#opt_gridline").click();
                },
                type: "NORMAL"
            },
            hk_border: {
                defaultHotkey: "B",
                name: "Grid Locations",
                keyDown: function() {
                    $('#opt_mapgrid').click();
                },
                type: "NORMAL"
            },
            hk_simple_draw: {
                defaultHotkey: "",
                name: "On/ off Simple draw",
                keyDown: function() {
                    $("#opt_simple_drawing").click();
                },
                type: "NORMAL"
            },
            hk_score: {
                defaultHotkey: "",
                name: "Show/ hide Score",
                keyDown: function() {
                    $("#opt_score").click();
                },
                type: "NORMAL"
            },
            hk_ste: {
                defaultHotkey: "",
                name: "Show/ hide STE",
                keyDown: function() {
                    $("#opt_ste").click();
                },
                type: "NORMAL"
            },
            hk_n16: {
                defaultHotkey: "",
                name: "Show/ hide [n/16]",
                keyDown: function() {
                    $("#opt_ball_total").click();
                },
                type: "NORMAL"
            },
            hk_auto_hide_mass: {
                defaultHotkey: "",
                name: "On/ off Auto hide mass",
                keyDown: function() {
                    $("#opt_auto_hide_mass").click();
                },
                type: "NORMAL"
            },
            hk_auto_hide_name: {
                defaultHotkey: "",
                name: "On/ off Auto hide name",
                keyDown: function() {
                    $("#opt_auto_hide_name").click();
                },
                type: "NORMAL"
            },
            hk_show_text_stroke_line: {
                defaultHotkey: "",
                name: "Show/ hide Text shadow",
                keyDown: function() {
                    $("#opt_show_text_stroke_line").click();
                },
                type: "NORMAL"
            },
            hk_minimap: {
                defaultHotkey: "ALT_M",
                name: "Show/ hide Minimap",
                keyDown: function() {
                    $("#opt_minimap").click();
                },
                type: "NORMAL"
            },
            hk_mousew: {
                defaultHotkey: "",
                name: "On/ off Mouse W",
                keyDown: function() {
                    $("#opt_mousew").click();
                },
                type: "NORMAL"
            },
            hk_send_msg: {
                defaultHotkey: "ENTER",
                name: "Chatbox send message",
                keyDown: function() {
                    chatRoom.enter();
                },
                type: "NORMAL"
            },
            hk_send_msg1: {
                defaultHotkey: "ALT_1",
                name: "Chatbox send message 1",
                keyDown: function() {
                    console.log("CHAT MESSAGE");
                    chatRoom.sendMessage(chatCommand.input_hk_send_msg1);
                },
                type: "TEXT"
            },
            hk_send_msg2: {
                defaultHotkey: "ALT_2",
                name: "Chatbox send message 2",
                keyDown: function() {
                    chatRoom.sendMessage(chatCommand.input_hk_send_msg2);
                },
                type: "TEXT"
            },
            hk_send_msg3: {
                defaultHotkey: "ALT_3",
                name: "Chatbox send message 3",
                keyDown: function() {
                    chatRoom.sendMessage(chatCommand.input_hk_send_msg3);
                },
                type: "TEXT"
            },
            hk_send_msg4: {
                defaultHotkey: "ALT_4",
                name: "Chatbox send message 4",
                keyDown: function() {
                    chatRoom.sendMessage(chatCommand.input_hk_send_msg4);
                },
                type: "TEXT"
            },
            hk_send_msg5: {
                defaultHotkey: "ALT_5",
                name: "Chatbox send message 5",
                keyDown: function() {
                    chatRoom.sendMessage(chatCommand.input_hk_send_msg5);
                },
                type: "TEXT"
            },
            hk_send_msg6: {
                defaultHotkey: "ALT_6",
                name: "Chatbox send message 6",
                keyDown: function() {
                    chatRoom.sendMessage(chatCommand.input_hk_send_msg6);
                },
                type: "TEXT"
            },
            hk_send_msg7: {
                defaultHotkey: "ALT_7",
                name: "Chatbox send message 7",
                keyDown: function() {
                    chatRoom.sendMessage(chatCommand.input_hk_send_msg7);
                },
                type: "TEXT"
            },
            hk_send_msg8: {
                defaultHotkey: "ALT_8",
                name: "Chatbox send message 8",
                keyDown: function() {
                    chatRoom.sendMessage(chatCommand.input_hk_send_msg8);
                },
                type: "TEXT"
            },
            hk_send_msg9: {
                defaultHotkey: "ALT_9",
                name: "Chatbox send message 9",
                keyDown: function() {
                    chatRoom.sendMessage(chatCommand.input_hk_send_msg9);
                },
                type: "TEXT"
            },
            hk_send_msg10: {
                defaultHotkey: "ALT_0",
                name: "Chatbox send message 10",
                keyDown: function() {
                    chatRoom.sendMessage(chatCommand.input_hk_send_msg10);
                },
                type: "TEXT"
            }
        };
    };
    this.createMessageDialog = function() {
        var $message;
        var $text;
        $text = $("<div class='modal-footer'>");
        $text.append("<button type='button' class='btn btn-default' data-dismiss='modal'>OK</button>");
        $message = $("<div class='modal-content'/>");
        $message.append($("<div class='modal-header'/>").append("<button type='button' class='close' data-dismiss='modal'>&times;</button><h4 id='message_dialog_title' class='modal-title'></h4>"));
        $message.append($("<div id='message_dialog_content' class='modal-body'>"));
        $message.append($text);
        $message = $("<div id='message_dialog' class='modal fade' role='dialog'/>").append("<div class='modal-dialog'/>").append($message);
        $("body").append($message);
        $("#message_dialog").modal({
            backdrop: "static",
            keyboard: false
        });
        $(document).on("shown.bs.modal", "#message_dialog", function() {
            var a = $("#message_dialog>.modal-content").outerHeight();
            var b = $(document).outerHeight();
            if (a > b) {
                $("#message_dialog").css("overflow", "auto");
            } else {
                $("#message_dialog").css("margin-top", b / 2 - a / 2 - 40);
            }
        });
        $(document).on("hide.bs.modal", "#message_dialog", function() {});
    };
    this.setUpHotKeyConfigPage = function() {
        $(".left-side > div:nth-child(2)").after('<div class="agario-panel agario-side-panel agarioProfilePanel level" style="display: block !important;text-align:center"><button type="button" class="btn btn-success btn-hotkey" data-toggle="modal" data-target="#hotkeys_setting">Hotkeys</button></div>');
        var body;
        var $rootElement;
        $rootElement = $('<div class="modal-footer" style="background: #222;">');
        body = $("<div class='modal-content' style='background: #222;'/>");
        body.append($("<div class='modal-header'/>").append("<button type='button' class='close' data-dismiss='modal'>&times;</button><h4 class='modal-title'>Hotkey Setup</h4>"));
        body.append($("<div id='hotkey_modal_body' class='modal-body'>").append(myApp.getHotkeyDivHtml()));
        body.append($rootElement);
        body = $("<div id='hotkeys_setting' class='modal fade' role='dialog'/>").append("<div class='modal-dialog'/>").append(body);
        $("body").append(body);
        $(document).on("hide.bs.modal", "#hotkeys_setting", function() {
            if (selectedHotkeyRow) {
                selectedHotkeyRow.removeClass("table-row-selected");
            }
            selectedHotkeyRow = null;
            myApp.refreshHotkeySettingPage();
        });
        $("#hotkey_table .row").not(".header").click(function() {
            if (selectedHotkeyRow) {
                selectedHotkeyRow.removeClass("table-row-selected");
            }
            selectedHotkeyRow = $(this);
            selectedHotkeyRow.addClass("table-row-selected");
        });
    };
    window.saveHotkeys = function() {
        var codeSegments = $(".hotkey");
        hotkeyMapping = {};
        var i = 0;
        for (; i < codeSegments.length; i++) {
            hotkeyMapping[$(codeSegments[i]).text()] = $(codeSegments[i]).attr("data-hotkeyid");
        }
        setLocalStorage("hotkeyMapping", hotkeyMapping);
        var guid;
        for (guid in chatCommand) {
            chatCommand[guid] = $("#" + guid).val();
        }
        setLocalStorage("chatCommand", chatCommand);
    };
    this.copyGameInfo = function() {
        var failuresLink;
        failuresLink = "Current IP = " + myApp.getCurrentIP();
        failuresLink += "\nRegion : " + $("#region option:selected").text().split(" ")[0];
        failuresLink += "\nGame mode : " + $("#gamemode option:selected").text();
        failuresLink += "\nParty Code : " + myApp.getCurrentPartyCode();
        var codeSegments = myApp.getLeaderBoard();
        if (codeSegments && 0 != codeSegments.length) {
            var i = 0;
            for (; i < codeSegments.length; i++) {
                failuresLink += "\n" + (i + 1) + ".  " + codeSegments[i];
            }
        }
        copyToClipboard(failuresLink);
    };
    window.resetDefaultHotkey = function() {
        var e;
        e = hotkeyMapping;
        defaultHotkeyMapping = {};
        var unlock;
        for (unlock in hotkeyConfig) {
            if (hotkeyConfig[unlock].defaultHotkey) {
                if ("" != hotkeyConfig[unlock].defaultHotkey) {
                    defaultHotkeyMapping[hotkeyConfig[unlock].defaultHotkey] = unlock;
                }
            }
        }
        hotkeyMapping = defaultHotkeyMapping;
        myApp.refreshHotkeySettingPage();
        hotkeyMapping = e;
        defaultHotkeyMapping = null;
        var val;
        for (val in defaultHotkeyMessageSend) {
            $("#" + val).val(defaultHotkeyMessageSend[val]);
        }
    };
    this.refreshHotkeySettingPage = function() {
        var codeSegments = $(".hotkey");
        var i = 0;
        for (; i < codeSegments.length; i++) {
            $(codeSegments[i]).text(" ");
        }
        var version;
        for (version in hotkeyMapping) {
            $("[data-hotkeyid=" + hotkeyMapping[version] + "]").text(version);
        }
        var val;
        for (val in chatCommand) {
            $("#" + val).val(chatCommand[val]);
        }
    };
    this.getHotkeyDivHtml = function() {
        var html = "";
        var fragment = $("<div id='hotkey_setting'></div>");
        var rendered = $("<div id='hotkey_table' class='table'></div>");
        var $message = $("<div class='row header' style='display:none;'></div>");
        $message.append($("<div class='cell' style='width:170px;'>Hotkey</div>"));
        $message.append($("<div class='cell' style='width:222px;'>Function</div>"));
        $message.append($("<div class='cell'>Message</div>"));
        rendered.append($message);
        $message = null;
        var type;
        for (type in hotkeyConfig) {
            $message = $("<div class='row'></div>");
            $message.append($("<div data-hotkeyId='" + type + "' class='cell hotkey'>" + getHotkeyById(type) + "</div>"));
            $message.append($("<div class='cell'>" + hotkeyConfig[type].name + "</div>"));
            if ("TEXT" == hotkeyConfig[type].type) {
                $message.append($("<div class='cell has-inputs'><input id='input_" + type + "' class='form-control dark-input' maxlength='200' type='text' value='" + chatCommand["input_" + type] + "'></input></div>"));
            } else {
                //$message.append($("<div class='cell'> / </div>"));
            }
            rendered.append($message);
        }
        return fragment.append(rendered), html += $("<p>Step 1: Click on the function item</p>")[0].outerHTML, html += $("<p>Step 2: Press wanted hotkey to modify</p>")[0].outerHTML, html += $("<p>Press [DEL] key to remove selected hotkey</p>")[0].outerHTML,
            html += $("<p>Allowed hotkey combinations: [CTRL] + [ALT] + 0-9, a-z, [TAB], [ENTER]</p>")[0].outerHTML, html += $("<br></br>")[0].outerHTML,
            html += fragment[0].outerHTML, $("<div/>").append(html).html();
    };
    this.checkVersion = function() {
        var string = getLocalStorage("lastestVersion");
        if (!(string && string == myApp.version)) {
            myApp.applyNewUpdate();
            setLocalStorage("lastestVersion", myApp.version);
        }
    };
    this.showAnnouncement = function() {};
    this.applyNewUpdate = function() {};
    this.setupHints = function() {};
    this.setupHintsImpl = function(node, newValue) {
        node.addClass("hint--bottom hint--rounded");
        node.attr("data-hint", newValue);
    };
    this.ajax = function(url, options, callback, uri) {
        uri = null;
        var request;
        try {
            request = new XMLHttpRequest;
        } catch (a) {
            try {
                request = new ActiveXObject("Msxml2.XMLHTTP");
            } catch (s) {
                try {
                    request = new ActiveXObject("Microsoft.XMLHTTP");
                } catch (l) {
                    return alert("Your browser does not support Ajax."), false;
                }
            }
        }
        return request.onreadystatechange = function() {
            if (4 == request.readyState) {
                callback(request);
            }
        }, request.open(options, url, true), request.send(uri), request;
    };
    this.getSkinImage = function(t) {
        return t && "" != t ? customSkin[t] ? customSkin[t] : (-1 == skinDownloadQueue.indexOf(t) && skinDownloadQueue.push(t), null) : null;
    };
    this.downloadSkin = function() {
        if (0 != skinDownloadQueue.length) {
            var task = skinDownloadQueue.shift();
            if (!customSkin[task]) {
                if (skinDownloadFail[task] && 5 < skinDownloadFail[task]) {
                    if (myApp.getCustomSkinUrl() === task) {
                        //$(".skin-url").val("").trigger("change"); 
						//asÃ­ estÃ¡ en alis
                    }
                } else {
                    window.postMessage({
                        action: Action.IMAGE,
                        data: task
                    }, "*");
                }
            }
        }
        setTimeout(myApp.downloadSkin, 2E3);
    };
    this.changePreviewImage = function(url) {
		//alert("Hola");
        $(".skin").fadeOut(315, function() {
            $(this).attr("src", url).bind("onreadystatechange load", function() {
                if (this.complete) {
                    $(this).fadeIn(315);
                }
            });
        });
    };
}

function ChatRoom() {
    this.container = "";
    this.isShow = true;
    this.lastMsg = "";
    this.width = 340;
    this.height = 350;
    var _this = this;
    var t = 0;
    this.createChatBox = function() {
        this.hide();
        $(".chat-area").hide();
        $(".chat").mouseup(function() {
            _this.resize();
        });
    };
    _this.resize = function() {
        if ($(".chat").width() != this.width || $(".chat").height() != this.height) {
            if ($(".chat").perfectScrollbar) {
                $(".chat").perfectScrollbar("update");
            }
        }
    };
    this.sendMessage = function(msg) {
        if (msg = msg.trim()) {
            if (!(2E3 > Date.now() - t && 50 > msg.length)) {
                conn.sendMessage({
                    sender: myApp.getName(),
                    msg: msg
                });
                this.lastMsg = msg;
                t = Date.now();
            }
        }
    };
    this.enter = function() {
        if (this.isFocus()) {
            this.sendMessage($(".chat-input").val());
            $(".chat-input").val("");
            $(".chat-input").blur();
            $(".chat-area").hide();
        } else {
            this.focus();
        }
    };
    this.popup = function(callback) {
        if (myApp.isEnableChatpopup) {
            if (!this.isShow) {
                if ($.toast) {
                    $.toast(callback);
                } else {
                    toastQueue.push(callback);
                }
            }
        }
    };
    this.popupInfo = function(text) {
        this.popup({
            text: escapeHtml(text),
            showHideTransition: "slide",
            icon: "info",
            bgColor: "rgba(10, 10, 10, 0.8)",
            allowToastClose: false,
            hideAfter: 15E3,
            stack: 10
        });
    };
    this.popupWarning = function(text) {
        this.popup({
            text: escapeHtml(text),
            showHideTransition: "slide",
            icon: "warning",
            bgColor: "rgba(10, 10, 10, 0.8)",
            allowToastClose: false,
            hideAfter: 15E3,
            stack: 10
        });
    };
    this.popupChat = function(data, msg) {
        var html = escapeHtml(data);
        var replaceHKGIcon = this.replaceHKGIcon(escapeHtml(msg));
        if ("\u4e0d\u7559\u540d [slick]" == data) {
            html = this.replaceHKGIcon(html);
        }
        this.popup({
            heading: '<span class="toast_sender">' + html + ": </span>",
            text: '<span class="toast_chatmsg">' + replaceHKGIcon + "</span>",
            showHideTransition: "fade",
            bgColor: "rgba(10, 10, 10, 0.8)",
            allowToastClose: false,
            hideAfter: 15E3,
            stack: 10
        });
    };
    this.showSystemMessage = function(m1) {
        this.showSystemMessageImpl(m1);
        this.popupInfo(m1);
    };
    this.showSystemWarning = function(m1) {
        this.showSystemMessageImpl(m1);
        this.popupWarning(m1);
    };
    this.showSystemMessageImpl = function(num) {
        if (myApp.showSystemMessage()) {
            $(".chat").append($("<div/>").append($("<span class='system'/>").text(this.getTimeStr() + num)));
            this.scrollDown();
        }
    };
    this.getTimeStr = function() {
        var now = new Date;
        var index = now.getMinutes();
        return index = 10 > index ? "0" + index : index, now.getHours() + ":" + index + " ";
    };
    this.receiveMessage = function(msg, message) {
        var tabContent = $("<div/>");
        var errors = $("<span class='time'>").text(this.getTimeStr());
        var size = $("<span class='sender'>").text(msg + " : ");
        if ("\u4e0d\u7559\u540d [slick]" == msg) {
            size.html(this.replaceHKGIcon(size.html()));
        }
        tabContent.append(errors);
        tabContent.append(size);
        errors = $("<span class='msg'>").text(message);
        errors.html(this.replaceHKGIcon(errors.html()));
        tabContent.append(errors);
        $(".chat").append(tabContent);
        this.scrollDown();
        this.popupChat(msg, message);
    };
    this.replaceHKGIcon = function(xhtml) {
        var query;
        for (query in hkgIcon) {
            xhtml = xhtml.replace(new RegExp(escapeRegex(query), "g"), '<img alt="$1" src="' + hkgIcon[query] + '">');
        }
        var images = $('img[alt="$1"]');
        var i = 0;
        for (; i < images.length; i++) {
            for (query in hkgIcon) {
                if (images[i].src == hkgIcon[query]) {
                    $(images[i]).attr("alt", query);
                    break;
                }
            }
        }
        return xhtml;
    };
    this.scrollDown = function() {
        if ($(".chat").perfectScrollbar) {
            $(".chat").scrollTop($(".chat").prop("scrollHeight"));
            $(".chat").perfectScrollbar("update");
        }
    };
    this.show = function() {
        $(".chat").show();
        this.isShow = true;
        this.scrollDown();
    };
    this.hide = function() {
        $(".chat").hide();
        this.isShow = false;
    };
    this.isFocus = function() {
        return $(".chat-input").is(":focus");
    };
    this.focus = function() {
        $(".chat-area").show();
        $(".chat-input").focus();
    };
    this.createScrollBar = function() {
        $(".chat").perfectScrollbar({
            minScrollbarLength: 50,
            suppressScrollX: false
        });
    };
}

function Minimap() {
    var canvas, ctx, options, context;
    var w = 180;
    var h = 180;
    var s = false;
    var v = {};
    this.createMap = function(s) {
        if (s) w = h = s;
        canvas = document.getElementById("minimap");
        ctx = canvas.getContext("2d");
        canvas.width = w;
        canvas.height = h;
        ctx.scale(1, 1);
        ctx.strokeStyle = "#333";
        ctx.fillStyle = "rgba(27,27,27,.5)";
        ctx.globalAlpha = .5;
        ctx.lineWidth = 2;
        ctx.strokeRect(0, 0, canvas.width, canvas.height);
        ctx.fillRect(0, 0, canvas.width, canvas.height);
        ctx.textAlign = "center";
        ctx.textBaseline = "middle";
        ctx.globalAlpha = 0.2;
        ctx.font = "11px Verdana";
        ctx.fillStyle = "#FFFFFF";
        ctx.fillText("A1", w / 5 / 2, h / 5 / 2);
        ctx.fillText("A2", w / 5 / 2 * 3, h / 5 / 2);
        ctx.fillText("A3", w / 5 / 2 * 5, h / 5 / 2);
        ctx.fillText("A4", w / 5 / 2 * 7, h / 5 / 2);
        ctx.fillText("A5", w / 5 / 2 * 9, h / 5 / 2);
        ctx.fillText("B1", w / 5 / 2, h / 5 / 2 * 3);
        ctx.fillText("B2", w / 5 / 2 * 3, h / 5 / 2 * 3);
        ctx.fillText("B3", w / 5 / 2 * 5, h / 5 / 2 * 3);
        ctx.fillText("B4", w / 5 / 2 * 7, h / 5 / 2 * 3);
        ctx.fillText("B5", w / 5 / 2 * 9, h / 5 / 2 * 3);
        ctx.fillText("C1", w / 5 / 2, h / 5 / 2 * 5);
        ctx.fillText("C2", w / 5 / 2 * 3, h / 5 / 2 * 5);
        ctx.fillText("C3", w / 5 / 2 * 5, h / 5 / 2 * 5);
        ctx.fillText("C4", w / 5 / 2 * 7, h / 5 / 2 * 5);
        ctx.fillText("C5", w / 5 / 2 * 9, h / 5 / 2 * 5);
        ctx.fillText("D1", w / 5 / 2, h / 5 / 2 * 7);
        ctx.fillText("D2", w / 5 / 2 * 3, h / 5 / 2 * 7);
        ctx.fillText("D3", w / 5 / 2 * 5, h / 5 / 2 * 7);
        ctx.fillText("D4", w / 5 / 2 * 7, h / 5 / 2 * 7);
        ctx.fillText("D5", w / 5 / 2 * 9, h / 5 / 2 * 7);
        ctx.fillText("E1", w / 5 / 2, h / 5 / 2 * 9);
        ctx.fillText("E2", w / 5 / 2 * 3, h / 5 / 2 * 9);
        ctx.fillText("E3", w / 5 / 2 * 5, h / 5 / 2 * 9);
        ctx.fillText("E4", w / 5 / 2 * 7, h / 5 / 2 * 9);
        ctx.fillText("E5", w / 5 / 2 * 9, h / 5 / 2 * 9);
        options = document.getElementById("minimapNode");
        context = options.getContext("2d");
        options.width = s;
        options.height = s;
        context.globalAlpha = 1;
        context.scale(1, 1);
        context.textAlign = "center";
        context.textBaseline = "middle";
        context.font = "13px Verdana";
        this.hide();
        setInterval(function() {
            minimap.drawNodes();
        }, 1E3 / 30);
    };
    this.uploadSelfPosition = function() {
        var m = gSelfMass;
        if (getCurrentX() && getCurrentY()) {
            s = true;
            conn.uploadCoords({
                x: getCurrentX(),
                y: getCurrentY(),
                m: m
            });
        } else {
            if (s) {
                conn.uploadCoords({
                    x: getCurrentX(),
                    y: getCurrentY(),
                    m: m
                });
                s = false;
            }
        }
    };
    this.isExists = function(dataAndEvents) {
        var i = 0;
        for (; i < nodeList.length; i++) {
            if (dataAndEvents == nodeList[i][0]) {
                return i;
            }
        }
        return null;
    };
    this.updateNode = function(obj) {
        var i;
        var node = obj.id;
        var l = obj.x;
        var lat = obj.y;
        var entityName = obj.name;
        if (i = this.isExists(node)) {
            nodeList[i][1] = entityName;
            nodeList[i][2] = l;
            nodeList[i][3] = lat;
            nodeList[i][7] = true;
            nodeList[i][4] = "#555555";
            nodeList[i][8] = Date.now();
            if (!(nodeList[i][12] && nodeList[i][13])) {
                nodeList[i][12] = l;
                nodeList[i][13] = lat;
            }
        } else {
            nodeList[nodeList.length] = [node, entityName, null, null, "#555555", null, null];
        }
    };
    this.addNode = function(mode) {
        nodeList[nodeList.length] = [mode.id, mode.name, null, null, nodeColor, mode.skinurl, mode.cellColor];
    };
    this.drawNodes = function() {
        var max = getLengthX();
        var s = getLengthY();
        context.clearRect(0, 0, options.width, options.height);
        var a = getCurrentX();
        var b = getCurrentY();
        if (a) {
            if (b) {
                v.x = nodeList[0][2];
                v.y = nodeList[0][3];
            }
        }
        nodeList[0][2] = a;
        nodeList[0][3] = b;
        nodeList[0][12] = a;
        nodeList[0][13] = b;
        nodeList[0][14] = gSelfMass;
        if (myApp.isSpectating) {
            nodeList[1][2] = getTop1X();
            nodeList[1][3] = getTop1Y();
            nodeList[1][12] = getTop1X();
            nodeList[1][13] = getTop1Y();
        }
        var i = 0;
        for (; i < nodeList.length; i++) {
            if (nodeList[i][2] && (nodeList[i][3] && (nodeList[i][12] && (nodeList[i][13] && "del" != nodeList[i][0])))) {
                var x;
                var y;
                var radius;
                radius = 1 == i ? 7 : 5;
                nodeList[i][2] = ~~nodeList[i][2];
                nodeList[i][3] = ~~nodeList[i][3];
                nodeList[i][12] = ~~nodeList[i][12];
                nodeList[i][13] = ~~nodeList[i][13];
                nodeList[i][12] += (max / 2 + nodeList[i][2] - (max / 2 + nodeList[i][12])) / 30;
                nodeList[i][13] += (s / 2 + nodeList[i][3] - (s / 2 + nodeList[i][13])) / 30;
                x = (max / 2 + nodeList[i][12]) / max * w;
                y = (s / 2 + nodeList[i][13]) / s * h;
                context.beginPath();
                context.arc(x, y, radius, 0, 2 * Math.PI, false); 
				// Pinta la cÃ©lula en el minimapa
                context.fillStyle = 1 > i ? "white" : nodeList[i][4];
                //context.strokeStyle = "rgba(51,51,51,0.5)";
                context.lineWidth = 1;
                context.fill();
                context.stroke();
                if (i > 1) {
                    context.fillStyle = "#bababa";
                    context.fillText(nodeList[i][1], x, y - 10);
                }
            }
        }
        if (v.x) {
            if (v.y) {
                if (!(a && b)) {
                    x = (max / 2 + v.x) / max * w;
                    y = (s / 2 + v.y) / s * h;
                    context.beginPath();
                    context.moveTo(x - 3, y - 3);
                    context.lineTo(x + 3, y + 3);
                    context.moveTo(x + 3, y - 3);
                    context.lineTo(x - 3, y + 3);
                    context.stroke();
                    context.lineWidth = 1;
                    context.strokeStyle = "#FFF";
                    context.stroke();
                }
            }
        }
    };
    this.hide = function() {
        $("#minimap").hide();
        $("#minimapNode").hide();
    };
    this.show = function() {
        $("#minimap").show();
        $("#minimapNode").show();
    };
    this.setDeadPosition = function(r) {
        v = r ? r : {};
    };
}

function Connection() {
    var msg;
    var self = this;
    self.connect = function() {
        socket = io("149.56.109.66:8017", {
            transports: ["websocket"]
        });
        socket.on("updateCoords", function(walkers) {
            minimap.updateNode(walkers);
        });
        socket.on("receiveMessage", function(data) {
            chatRoom.receiveMessage(data.sender, data.msg);
        });
    };
    self.emit = function(name, data) {
        socket.emit(name, data);
    };
    self.joinRoom = function(value) {
        if (msg) {
            self.leaveRoom(msg);
        }
        if ("" != $(".partyToken").val()) {
            self.emit("joinRoom", {
                p: value,
                a: 1
            });
            msg = value;
        }
    };
    self.leaveRoom = function(er) {
        self.emit("leaveRoom", er);
    };
    self.uploadCoords = function(data) {
        data.name = myApp.getName();
        data.serverAddress = myApp.getCurrentPartyCode();
        data.timeStamp = Date.now();
        data.socketRoom = msg;
        self.emit("coords", data);
    };
    self.sendMessage = function(message) {
        message.socketRoom = msg;
        if ("" != $(".partyToken").val()) {
            self.emit("sendMessage", message);
        }
    };
}

function isValidHotKey(e) {
    return 48 <= e.keyCode && 57 >= e.keyCode || (65 <= e.keyCode && 90 >= e.keyCode || (9 == e.keyCode || 13 == e.keyCode || e.keyCode == 192)) ? true : false;
}

function getPressedKey(e) {
    var optsData = "";
    return e.ctrlKey && (optsData += "CTRL_"), e.altKey && (optsData += "ALT_"), optsData = 9 == e.keyCode ? optsData + "TAB" : 13 == e.keyCode ? optsData + "ENTER" : 192 == e.keyCode ? optsData + "~" : optsData + String.fromCharCode(e.keyCode);
}

function getHotkeyById(keepData) {
    var unlock;
    for (unlock in hotkeyMapping) {
        if (hotkeyMapping[unlock] == keepData) {
            return unlock;
        }
    }
    return "";
}

function copyToClipboard(el) {
    window.postMessage({
        action: Action.COPY,
        data: el
    }, "*");
}

function escapeRegex(string) {
    return string.replace(/[\-\[\]{}()*+?.,\\\^$|#\s]/g, "$&");
}

function drawMinimapNodes() {
    minimap.uploadSelfPosition();
    setTimeout(drawMinimapNodes, 1E3);
}

function updateGameInfoDiv() {
    if ($("#overview").is(":visible")) {
        myApp.updateLBInfo();
    }
    setTimeout(updateGameInfoDiv, 1E3);
}

function clearOldNodesData() {
    var i = 1;
    for (; i < nodeList.length; i++) {
        var t = nodeList[i][8];
        if (t) {
            if (5E3 < Date.now() - t) {
                if (2 > i) {
                    nodeList[i][2] = null;
                    nodeList[i][3] = null;
                } else {
                    nodeList[i][0] = "del";
                }
            }
        }
    }
    setTimeout(clearOldNodesData, 5E3);
}

function updateLbDiv() {
    if ($(".leaderboard").is(":visible")) {
        var apps = getLB();
        var codeSegments = getSelfIDs();
        var str = "";
        if (apps) {
            var a = 0;
            for (; a < apps.length; a++) {
                var left = false;
                var i = 0;
                for (; i < codeSegments.length; i++) {
                    if (codeSegments[i] == apps[a].id) {
                        left = true;
                        break;
                    }
                }
                i = apps[a].name ? escapeHtml(apps[a].name) : "An unnamed cell";
                str = left ? str + "<div class='self'>" : str + "<div>";
                //str += a + 1 + ". " + i + "</div>";
                str += i + "&nbsp;&nbsp;<strong>" + (a + 1) + "</strong></div>";
            }
        }
        $('.leaderboard-players').html(str);
    }
    setTimeout(updateLbDiv, 1E3);
}

function updateScoreDiv() {
    var message = getHighestScore();
    var json = getCell();
    var string = [];
    if (0 != message) {
        if (myApp.isShowScroll) {
            string.push("Score: " + ~~(message / 100));
        }
        if (json) {
            if (0 < json.length) {
                if (myApp.isShowSTE) {
                    message = myApp.getSTE(json);
                    string.push("STE: " + message);
                }
                if (myApp.isShowBallTotal) {
                    string.push("[" + json.length + "/16]");
                }
            }
        }
    }
    if (myApp.isShowFPS) {
        json = getFPS();
        if (50 >= json) {
            json += 8;
        } else {
            if (45 >= json) {
                json += 10;
            } else {
                if (40 >= json) {
                    json += 15;
                }
            }
        }
        //string.push("FPS: " + json + "  " + "Draw Time: " + drawTime + "  " + "Net Update: " + window.netUpdate);
        string.push("FPS: " + json);
    }
    if (isFreeSpec()) {
        if (myApp.specTeammate) {
            if (myApp.isStopMovement) {
                if (nodeList[myApp.specTeammate]) {
                    string.push("SPEC: " + nodeList[myApp.specTeammate][1]);
                }
            }
        }
    }
    if (myApp.testing) {
        string.push("*** TESTING ***");
    }
    if (0 < string.length) {
        if (!$(".stats").is(":visible")) {
            $(".stats").show();
        }
        var blob = string.join("&nbsp;&nbsp;&nbsp;").trim();
        $('.stats').html(blob);
    } else {
        $(".stats").hide();
    }
    setTimeout(updateScoreDiv, 500);
}
var URL_MESSAGE = "https://googledrive.com/host/0Bx5EmU2kLXq9alVNVTQxX0FFd1k/_message.txt";
var URL_JS_FOLDER = "https://googledrive.com/host/0Bx5EmU2kLXq9alVNVTQxX0FFd1k/";
var gSelfMass = 100;
var testingVal = 29;
var testingCount = 0;
var testingInd = false;
var spectateMode;
var myApp;
var nodeList = [];
var chatRoom = null;
var minimap = null;
var socket = null;
var currentIP = "";
var teamname = "HKG";
var defaultTeamname = "HKG";
var socketRetryInterval;
var isSocketReady = false;
var isChangeName = false;
var conn = null;
var reconnectCount = 0;
var updateLBCount = 0;
var tmpTeamname = "";
var defaultImage = new Image;
defaultImage.src = "data:image/svg+xml;base64,PD94bWwgdmVyc2lvbj0iMS4wIiBlbmNvZGluZz0idXRmLTgiPz4NCjwhLS0gR2VuZXJhdG9yOiBBZG9iZSBJbGx1c3RyYXRvciAxNi4yLjEsIFNWRyBFeHBvcnQgUGx1Zy1JbiAuIFNWRyBWZXJzaW9uOiA2LjAwIEJ1aWxkIDApICAtLT4NCjwhRE9DVFlQRSBzdmcgUFVCTElDICItLy9XM0MvL0RURCBTVkcgMS4xLy9FTiIgImh0dHA6Ly93d3cudzMub3JnL0dyYXBoaWNzL1NWRy8xLjEvRFREL3N2ZzExLmR0ZCI+DQo8c3ZnIHZlcnNpb249IjEuMSIgaWQ9IkxheWVyXzEiIHhtbG5zPSJodHRwOi8vd3d3LnczLm9yZy8yMDAwL3N2ZyIgeG1sbnM6eGxpbms9Imh0dHA6Ly93d3cudzMub3JnLzE5OTkveGxpbmsiIHg9IjBweCIgeT0iMHB4Ig0KCSB3aWR0aD0iNTEycHgiIGhlaWdodD0iNTEycHgiIHZpZXdCb3g9IjAgMCA1MTIgNTEyIiBzdHlsZT0iZW5hYmxlLWJhY2tncm91bmQ6bmV3IDAgMCA1MTIgNTEyOyIgeG1sOnNwYWNlPSJwcmVzZXJ2ZSI+DQo8Zz4NCgk8Zz4NCgkJPHBhdGggZD0iTTI1Niw0OEMxNDEuMSw0OCw0OCwxNDEuMSw0OCwyNTZzOTMuMSwyMDgsMjA4LDIwOGMxMTQuOSwwLDIwOC05My4xLDIwOC0yMDhTMzcwLjksNDgsMjU2LDQ4eiBNMjU2LDQ0Ni43DQoJCQljLTEwNS4xLDAtMTkwLjctODUuNS0xOTAuNy0xOTAuN2MwLTEwNS4xLDg1LjUtMTkwLjcsMTkwLjctMTkwLjdjMTA1LjEsMCwxOTAuNyw4NS41LDE5MC43LDE5MC43DQoJCQlDNDQ2LjcsMzYxLjEsMzYxLjEsNDQ2LjcsMjU2LDQ0Ni43eiIvPg0KCTwvZz4NCjwvZz4NCjxnPg0KCTxnPg0KCQk8cGF0aCBkPSJNMjU2LDk2Yy04OC40LDAtMTYwLDcxLjYtMTYwLDE2MGMwLDg4LjQsNzEuNiwxNjAsMTYwLDE2MGM4OC40LDAsMTYwLTcxLjYsMTYwLTE2MEM0MTYsMTY3LjYsMzQ0LjQsOTYsMjU2LDk2eiIvPg0KCTwvZz4NCjwvZz4NCjwvc3ZnPg0K";
var customSkin = {
    "": defaultImage
};
var announcementTxt = "";
var Action = {
    COPY: "",//COPY: "HKGAGARTOOLCOPY",
    IMAGE: "",//IMAGE: "HKGAGARTOOLIMAGE",
    FINISH: ""//FINISH: "HKGAGARTOOLFINISH"
};
var isJoinedGame = false;
var hotkeyConfig = {};
var hotkeyMapping = {};
var teammateIdt = {};
var defaultHotkeyMapping = {};
var selectedHotkeyRow;
var chatCommand = {};
var isWindowFocus = true;
var skinDownloadQueue = [];
var skinDownloadFail = {};
var toastQueue = [];
var defaultSkin = "http://i.imgur.com/vX3zql0.png";
var defaultSkin2 = "http://i.imgur.com/EmPUIjo.png";
var gm;
var defaultHotkeyMessageSend = {
    input_hk_send_msg1: "Need backup!",
    input_hk_send_msg2: "Need a teammate!",
    input_hk_send_msg3: "Pop him!",
    input_hk_send_msg4: "We need to run!",
    input_hk_send_msg5: "Tricksplit!",
    input_hk_send_msg6: "Lets bait! ",
    input_hk_send_msg7: "Split into me!",
    input_hk_send_msg8: "Feed me!",
    input_hk_send_msg9: "Tank the virus!",
    input_hk_send_msg10: "Roger that!"
};
var hkgIcon = {};
var selected_profile = 0;

var player_profile = [
						{
							name: "Profile 1",
							team: "Team1",
							skinurl: defaultSkin
						}, 
						{
							name: "Profile 2",
							team: "Team2",
							skinurl: defaultSkin2//skinurl: "https://181cfbce4e26cf7f3642ac9e82d9e05ca7869931-www.googledrive.com/host/0B6Qc5Ss9h9-sfmhZMXBsRHYySVZFTzl5cVFkX3VPYjlDU3JJVmhwbzV2LVc5MGk4c3RHVDg/circles.png"
						}, 
						{
							name: "Profile 3",
							team: "Team3",
							skinurl: defaultSkin //skinurl: "https://181cfbce4e26cf7f3642ac9e82d9e05ca7869931-www.googledrive.com/host/0B6Qc5Ss9h9-sfmhZMXBsRHYySVZFTzl5cVFkX3VPYjlDU3JJVmhwbzV2LVc5MGk4c3RHVDg/1.png"
						}, 
						{
							name: "Profile 4",
							team: "Team4",
							skinurl: defaultSkin2//skinurl: "https://181cfbce4e26cf7f3642ac9e82d9e05ca7869931-www.googledrive.com/host/0B6Qc5Ss9h9-sfmhZMXBsRHYySVZFTzl5cVFkX3VPYjlDU3JJVmhwbzV2LVc5MGk4c3RHVDg/1.png"
						}, 
						{
							name: "Profile 5",
							team: "Team5",
							skinurl: defaultSkin//skinurl: "https://181cfbce4e26cf7f3642ac9e82d9e05ca7869931-www.googledrive.com/host/0B6Qc5Ss9h9-sfmhZMXBsRHYySVZFTzl5cVFkX3VPYjlDU3JJVmhwbzV2LVc5MGk4c3RHVDg/1.png"
						}, 
						{
							name: "Profile 6",
							team: "Team6",
							skinurl: defaultSkin2//skinurl: "https://181cfbce4e26cf7f3642ac9e82d9e05ca7869931-www.googledrive.com/host/0B6Qc5Ss9h9-sfmhZMXBsRHYySVZFTzl5cVFkX3VPYjlDU3JJVmhwbzV2LVc5MGk4c3RHVDg/1.png"
						}, 
						{
							name: "Profile 7",
							team: "Team7",
							skinurl: defaultSkin//skinurl: "https://181cfbce4e26cf7f3642ac9e82d9e05ca7869931-www.googledrive.com/host/0B6Qc5Ss9h9-sfmhZMXBsRHYySVZFTzl5cVFkX3VPYjlDU3JJVmhwbzV2LVc5MGk4c3RHVDg/1.png"
						}, 
						{
							name: "Profile 8",
							team: "Team8",
							skinurl: defaultSkin2//skinurl: "https://181cfbce4e26cf7f3642ac9e82d9e05ca7869931-www.googledrive.com/host/0B6Qc5Ss9h9-sfmhZMXBsRHYySVZFTzl5cVFkX3VPYjlDU3JJVmhwbzV2LVc5MGk4c3RHVDg/1.png"
						}, 
						{
							name: "Profile 9",
							team: "Team9",
							skinurl: defaultSkin//skinurl: "https://181cfbce4e26cf7f3642ac9e82d9e05ca7869931-www.googledrive.com/host/0B6Qc5Ss9h9-sfmhZMXBsRHYySVZFTzl5cVFkX3VPYjlDU3JJVmhwbzV2LVc5MGk4c3RHVDg/1.png"
						}, 
						{
							name: "Profile 10",
							team: "Team10",
							skinurl: defaultSkin2//skinurl: "https://181cfbce4e26cf7f3642ac9e82d9e05ca7869931-www.googledrive.com/host/0B6Qc5Ss9h9-sfmhZMXBsRHYySVZFTzl5cVFkX3VPYjlDU3JJVmhwbzV2LVc5MGk4c3RHVDg/1.png"
						}
					];
myApp = new MyApp, myApp.init();
var playerDetailsByIdentifier = {};
var playerDetailsByNick = {};
var announcementSent = false;
! function(self, jQuery) {
    function init() {
        Ze = true;
        cnv = cv = document.getElementById("canvas");
        document.getElementById("hud").onmousemove = function(e) {
            x = e.clientX;
            y = e.clientY;
            paint();
        };
        context = cnv.getContext("2d");
        if (/firefox/i.test(navigator.userAgent)) {
            document.addEventListener("DOMMouseScroll", onDocumentMouseScroll, false);
        } else {
            document.body.onmousewheel = onDocumentMouseScroll;
        }
        var ne = false;
        var n = false;
        var elm = false;
        self.onkeydown = function(event) {
            if (32 == event.keyCode) {
                if (!chatRoom.isFocus()) {
                    if (!ne) {
                        reset();
                        emit(17);
                        ne = true;
                    }
                }
            }
            if (81 == event.keyCode) {
                if (!n) {
                    emit(18);
                    n = true;
                }
            }
            if (87 == event.keyCode) {
                if (!chatRoom.isFocus()) {
                    if (!elm) {
                        reset();
                        emit(21);
                        elm = true;
                    }
                }
            }
            if (isJoinedGame && !$("#overview").is(":visible") || spectateMode) {
                if (27 == event.keyCode) {
                    event.preventDefault();
                    focus(300);
                }
            } else {
                if (27 == event.keyCode) {
                    event.preventDefault();
                    $(".play-button").trigger("click");
                }
            }
        };
        self.onkeyup = function(event) {
            if (32 == event.keyCode) {
                ne = false;
            }
            if (87 == event.keyCode) {
                elm = false;
            }
            if (81 == event.keyCode) {
                if (n) {
                    emit(19);
                    n = false;
                }
            }
        };
        self.onblur = function() {
            emit(19);
            elm = n = ne = false;
        };
        self.onresize = update;
        self.requestAnimationFrame(which);
        setInterval(reset, 42);
        refresh();
        focus(0);
        update();
        if (self.location.hash) {
            if (6 <= self.location.hash.length) success(self.location.hash);
        }
    }

    function onDocumentMouseScroll(event) {
        if (!$('#overview').is(':visible')) {
            if (myApp.isEnableZoom) {
                text *= Math.pow(myApp.getZoomSpeed(), event.wheelDelta / -120 || (event.detail || 0));
                if (myApp.getZoomLimit() > text) text = myApp.getZoomLimit();
                if (text > 1 / scale) text = 1 / scale;
            }
        }
    }

    function bind(type) {
        var p = null;
        if (0 < simpleExpected.playerCells().length) {
            p = simpleExpected.playerCells()[0];
            p = p.name + p.color;
        }
        var xs = jQuery(".skin-url").val();
        if (-1 != xs.indexOf("!!")) {
            try {
                atob(xs.slice(2));
            } catch (i) {}
        }
        return {
            displayName: jQuery(".nick").val(),
            action: type,
            socketRoom: myApp.getRoom(),
            identifier: p,
            url: myApp.getCustomSkinUrl(),
            nick: jQuery(".nick").val(),
            team: jQuery(".team").val(),
            token: myApp.getCurrentPartyCode()
        };
    }

    function resolve() {
        if (!announcementSent) {
            if (0 < simpleExpected.playerCells().length) {
                announcementSent = true;
                var data = bind("join");
                playerDetailsByIdentifier[data.identifier] = data;
                playerDetailsByNick[data.nick] = data;
                conn.emit("playerEntered", data);
            } else {
                setTimeout(resolve, 100);
            }
        }
    }

    function paint() {
        if (myApp.isStopMovement) {
            minX = chunk;
            t = loc;
        } else {
            minX = (x - width / 2) / scale + centerX;
            t = (y - height / 2) / scale + centerY;
        }
    }

    function _init() {
        jQuery("#overview").fadeOut(500);
        from = to = false;
        refresh();
    }

    function focus(outstandingDataSize) {
        if (!to) {
            if (!from) {
                b = null;
                if (1E3 > outstandingDataSize) newEnd = 1;
                to = true;
                jQuery("#overview").fadeIn(500);
            }
        }
    }

    function refresh() {
        if (jQuery("#region").val()) {
            self.localStorage.location = jQuery("#region").val();
        } else {
            if (self.localStorage.location) {
                jQuery("#region").val(self.localStorage.location);
            }
        }
        if (jQuery("#region").val()) {
            jQuery("#locationKnown").append(jQuery("#region"));
        } else {
            jQuery("#locationUnknown").append(jQuery("#region"));
        }
    }

    function _(key) {
        return self.i18n[key] || (self.i18n_dict.en[key] || key);
    }

    function send() {
        if (Ze) {
            if (value) {
                jQuery("#connecting").show()
            }
        }
    }

    function open(url, a) {
        result = [];
        data = [];
        window.queue = {};
        list = [];
        siblings = [];
        users = [];
        img = angles = null;
        closingAnimationTime = 0;
        matchEnd = false;
        ws = new WebSocket(url);
        window.webSocket = ws;
        window.urlSocket = url;
        ws.binaryType = "arraybuffer";
        ws.onopen = function() {
            var buf;
            buf = encode(5);
            buf.setUint8(0, 254);
            buf.setUint32(1, 5, true);
            cb(buf);
            buf = encode(5);
            buf.setUint8(0, 255);
            buf.setUint32(1, 154669603, true);
            cb(buf);
        };
        ws.onmessage = onmessage;
        ws.onclose = listener;
        ws.onerror = function() {};
        $("#privateForm").val(url);
    }

    function encode(expectedNumberOfNonCommentArgs) {
        return new DataView(new ArrayBuffer(expectedNumberOfNonCommentArgs));
    }

    function cb(s) {
        fx++;
        ws.send(s.buffer);
    }

    function listener(a) {
        if (matchEnd) {
            backoff = 500;
        }
        // Server is full
        var reason = `${a.reason}`;
        console.log(reason);
        if (reason == 'Server Full') {
            $.toast({
                heading: '<span id="server-toast" class="toast_sender">Connection Closed: </span>',
                text: `<span class="toast_chatmsg">${a.reason}</span>`,
                icon: 'info',
                showHideTransition: 'plain',
                bgColor: 'rgba(10, 10, 10, 0.95)',
                allowToastClose: false,
                hideAfter: 2500,
                stack: 5
            });
        }
        setTimeout(function () {
            if (reason !== 'Server Full') {
                $.toast({
                    heading: '<span id="server-toast" class="toast_sender">SERVER:</span>',
                    text: '<span class="toast_chatmsg">Server has been restarted</span>',
                    icon: 'info',
                    showHideTransition: 'plain',
                    bgColor: 'rgba(10, 10, 10, 0.95)',
                    allowToastClose: false,
                    hideAfter: 2500,
                    stack: 5
                });
            }
            setTimeout(function () {
                if (!handler()) {
                    connect($("#privateForm").val());
                    setTimeout(function () {
                        $(".play-button").click();
                    }, 750);
                }
            }, backoff * 2);
        }, backoff);
        backoff *= 2;
    }

    function onmessage(a) {
        var now = +new Date();
        window.lastPacketTime = now;
        parse(new DataView(a.data));
    }

    function parse(view) {
        function encode() {
            var str = "";
            for (;;) {
                var b = view.getUint16(offset, true);
                if (offset += 2, 0 == b) {
                    break;
                }
                str += String.fromCharCode(b);
            }
            return str;
        }
        clockseq++;
        var offset = 0;
        switch (240 == view.getUint8(offset) && (offset += 5), view.getUint8(offset++)) {
            case 16:
                fn(view, offset);
                break;
            case 17:
                chunk = view.getFloat32(offset, true);
                offset += 4;
                loc = view.getFloat32(offset, true);
                offset += 4;
                var col = view.getFloat32(offset, true);
                column = col;
                if (!myApp.isEnableLockZoom) {
                    crashed = col;
                }
                offset += 4;
                break;
            case 18:
                result = [];
                data = [];
                window.queue = {};
                list = [];
                break;
            case 20:
                data = [];
                result = [];
                break;
            case 21:
                fragment = view.getInt16(offset, true);
                offset += 2;
                m = view.getInt16(offset, true);
                offset += 2;
                if (!Xe) {
                    Xe = true;
                    node = fragment;
                    n = m;
                }
                break;
            case 32:
                result.push(view.getUint32(offset, true));
                offset += 4;
                break;
            case 49:
                if (null != angles) {
                    break;
                }
                col = view.getUint32(offset, true);
                offset += 4;
                users = [];
                var arg = 0;
                for (; col > arg; ++arg) {
                    var matches = view.getUint32(offset, true);
                    offset += 4;
                    users.push({
                        id: matches,
                        name: encode()
                    });
                }
                break;
            case 50:
                angles = [];
                col = view.getUint32(offset, true);
                offset += 4;
                arg = 0;
                for (; col > arg; ++arg) {
                    angles.push(view.getFloat32(offset, true));
                    offset += 4;
                }
                create();
                break;
            case 64:
                col = view.getFloat64(offset, true);
                offset += 8;
                arg = view.getFloat64(offset, true);
                offset += 8;
                matches = view.getFloat64(offset, true);
                offset += 8;
                var current = view.getFloat64(offset, true);
                offset += 8;
                if (inArray(matches - col, current - arg)) {
                    right = col;
                    top = arg;
                    left = matches;
                    computed = current;
                } else {
                    if (inArray(col, layers)) {
                        if (matches - stack > 0.01 || -0.01 > matches - stack) {
                            right = col;
                            left = col + 14142.135623730952;
                        }
                    }
                    if (col - layers > 0.01 || -0.01 > col - layers) {
                        if (inArray(matches, stack)) {
                            left = matches;
                            right = matches - 14142.135623730952;
                        }
                    }
                    if (arg - dependencies > 0.01 || -0.01 > arg - dependencies) {
                        if (inArray(current, before)) {
                            computed = current;
                            top = current - 14142.135623730952;
                        }
                    }
                    if (inArray(arg, dependencies)) {
                        if (current - before > 0.01 || -0.01 > current - before) {
                            top = arg;
                            computed = arg + 14142.135623730952;
                        }
                    }
                    if (right > col) {
                        right = col;
                        left = col + 14142.135623730952;
                    }
                    if (matches > left) {
                        left = matches;
                        right = matches - 14142.135623730952;
                    }
                    if (top > arg) {
                        top = arg;
                        computed = arg + 14142.135623730952;
                    }
                    if (current > computed) {
                        computed = current;
                        top = current - 14142.135623730952;
                    }
                    layers = col;
                    dependencies = arg;
                    before = current;
                    stack = matches;
                }
                myApp.afterGameLoaded();
                break;
            case 81:
                var length = view.getUint32(offset, true);
                offset += 4;
                var bytes = view.getUint32(offset, true);
                offset += 4;
                var index = view.getUint32(offset, true);
                offset += 4;
        }
    }

    function fn(view, offset) {
        function readFile() {
            var str = "";
            for (;;) {
                var b = view.getUint16(offset, true);
                if (offset += 2, 0 == b) {
                    break;
                }
                str += String.fromCharCode(b);
            }
            return str;
        }

        function getString() {
            var str = "";
            for (;;) {
                var b = view.getUint8(offset++);
                if (0 == b) {
                    break;
                }
                str += String.fromCharCode(b);
            }
            return str;
        }
        min = max = Date.now();
        if (!matchEnd) {
            matchEnd = true;
            stop();
        }
        Ee = false;
        var id = view.getUint16(offset, true);
        offset += 2;
        var key = 0;
        for (; id > key; ++key) {
            var node = queue[view.getUint32(offset, true)];
            var obj = queue[view.getUint32(offset + 4, true)];
            offset += 8;
            if (node) {
                if (obj) {
                    obj.R();
                    obj.o = obj.x;
                    obj.p = obj.y;
                    obj.n = obj.size;
                    obj.C = node.x;
                    obj.D = node.y;
                    obj.m = obj.size;
                    obj.K = max;
                    setData(node, obj);
                }
            }
        }
        key = 0;
        for (; id = view.getUint32(offset, true), offset += 4, 0 != id;) {
            ++key;
            var m;
            node = view.getInt32(offset, true);
            offset += 4;
            obj = view.getInt32(offset, true);
            offset += 4;
            m = view.getInt16(offset, true);
            offset += 2;
            var item = view.getUint8(offset++);
            var value = view.getUint8(offset++);
            var T = view.getUint8(offset++);
            value = flush(item << 16 | value << 8 | T);
            T = view.getUint8(offset++);
            var el = !!(1 & T);
            var j = !!(16 & T);
            var comment = null;
            if (2 & T) {
                offset += 4 + view.getUint32(offset, true);
            }
            if (4 & T) {
                comment = getString();
            }
            var input = readFile();
            item = null;
            if (queue.hasOwnProperty(id)) {
                item = queue[id];
                item.J();
                item.o = item.x;
                item.p = item.y;
                item.n = item.size;
                item.color = value;
            } else {
                item = new set(id, node, obj, m, value, input);
                list.push(item);
                queue[id] = item;
                item.ia = node;
                item.ja = obj;
            }
            item.f = el;
            item.j = j;
            item.C = node;
            item.D = obj;
            item.m = m;
            item.K = max;
            item.T = T;
            if (comment) {
                item.V = comment;
            }
            if (input) {
                item.t(input);
            }
            if (-1 != result.indexOf(id)) {
                if (-1 == data.indexOf(item)) {
                    data.push(item);
                    if (1 == data.length) {
                        centerX = item.x;
                        centerY = item.y;
                        removeEventListener();
                        $('#overview').fadeOut(500);
                        a = [];
                        pauseText = 0;
                        col = data[0].color;
                        Bt = true;
                        near = Date.now();
                        count = path = name = 0;
                    }
                }
            }
        }
        node = view.getUint32(offset, true);
        offset += 4;
        key = 0;
        for (; node > key; key++) {
            id = view.getUint32(offset, true);
            offset += 4;
            item = queue[id];
            if (null != item) {
                item.R();
            }
        }
        if (Ee) {
            if (0 == data.length) {
                myApp.onDead();
                far = Date.now();
                Bt = false;
                if (!to) {
                    if (!from) {
                        if (connected) {
                            DrawPolyline();
                            from = true;
                            $('#overview').fadeIn(500);
                        } else {
                            focus(1500);
                        }
                    }
                }
            }
        }
    }

    function stop() {
        c = "";
        jQuery("#connecting").hide();
        writeUTFBytes();
        if (save) {
            save();
            save = null;
        }
        if (null != tref) {
            clearTimeout(tref);
        }
        tref = setTimeout(function() {
            if (self.ga) {
                ++millis;
                self.ga("set", "dimension2", millis);
            }
        }, 1E4);
    }

    function reset() {
        if (!myApp.isStopMovement && handler()) {
            var x0 = x - width / 2;
            var x1 = y - height / 2;
            if (!(64 > x0 * x0 + x1 * x1)) {
                if (!(0.01 > Math.abs(maxX - minX) && 0.01 > Math.abs(t1 - t))) {
                    maxX = minX;
                    t1 = t;
                    x0 = encode(13);
                    x0.setUint8(0, 16);
                    x0.setInt32(1, minX, true);
                    x0.setInt32(5, t, true);
                    x0.setUint32(9, 0, true);
                    cb(x0);
                }
            }
        }
    }

    function inArray(arr, array) {
        return 0.01 > arr - array && arr - array > -0.01;
    }

    function writeUTFBytes() {
        if (handler() && (matchEnd && null != b)) {
            var buf = encode(1 + 2 * b.length);
            buf.setUint8(0, 0);
            var bi = 0;
            for (; bi < b.length; ++bi) {
                buf.setUint16(1 + 2 * bi, b.charCodeAt(bi), true);
            }
            cb(buf);
            b = null;
        }
    }

    function handler() {
        return null != ws && ws.readyState == ws.OPEN;
    }

    function emit(expectedNumberOfNonCommentArgs) {
        if (handler()) {
            var buf = encode(1);
            buf.setUint8(0, expectedNumberOfNonCommentArgs);
            cb(buf);
        }
    }

    function oncomplete() {
        if (handler() && null != window.userToken) {
            var buf = encode(2 + userToken.length);
            buf.setUint8(0, 82);
            buf.setUint8(1, 1);
            var i = 0;
            for (; i < window.userToken.length; ++i) {
                buf.setUint8(i + 2, window.userToken.charCodeAt(i));
            }
            cb(buf);
        }
    }

    function update() {
        width = 1 * self.innerWidth;
        height = 1 * self.innerHeight;
        cv.width = cnv.width = width;
        cv.height = cnv.height = height;
        var child = jQuery("#helloContainer");
        child.css("transform", "none");
        var b = child.height();
        var a = self.innerHeight;
        if (b > a / 1.1) {
            child.css("transform", "translate(-50%, -50%) scale(" + a / b / 1.1 + ")");
        } else {
            child.css("transform", "translate(-50%, -50%)");
        }
        render();
    }

    function requestAnimationFrame() {
        return 1 * Math.max(height / 1080, width / 1920) * text;
    }

    function frame() {
        if (0 != data.length) {
            if (myApp.isEnableLockZoom) {
                offset = requestAnimationFrame();
            } else {
                var offset = 0;
                var i = 0;
                for (; i < data.length; i++) {
                    offset += data[i].size;
                }
                offset = Math.pow(Math.min(64 / offset, 1), 0.4) * requestAnimationFrame();
            }
            scale = (9 * scale + offset) / 10;
        }
    }

    function render() {
        //var renderStart = +new Date();
        //var renderCells = 0;
        //window.drawTime = 0;
        var j;
        var diff = Date.now();
        if (++target, max = diff, 0 < data.length) {
            frame();
            var pos = j = 0;
            var c = 0;
            for (; c < data.length; c++) {
                data[c].J();
                j += data[c].x / data.length;
                pos += data[c].y / data.length;
            }
            chunk = j;
            loc = pos;
            crashed = scale;
            if (myApp.testing) {
                centerX = (testingVal * centerX + chunk) / (testingVal + 1);
                centerY = (testingVal * centerY + loc) / (testingVal + 1);
            } else {
                centerX = (centerX + j) / 2;
                centerY = (centerY + pos) / 2;
            }
        } else {
            centerX = (29 * centerX + chunk) / 30;
            centerY = (29 * centerY + loc) / 30;
            if (!myApp.onDead()) scale = (9 * scale + crashed * requestAnimationFrame()) / 10;
        }
        _root = null;
        paint();
        if (!dest) context.clearRect(0, 0, width, height);
        if (dest) {
            context.fillStyle = color ? "#111111" : "#F2FBFF";
            context.globalAlpha = 0.05;
            context.fillRect(0, 0, width, height);
            context.globalAlpha = 1;
        } else {
            redraw();
        }
        list.sort(function(a, b) {
            return a.size == b.size ? a.id - b.id : a.size - b.size;
        });
        context.save();
        context.translate(width / 2, height / 2);
        context.scale(scale, scale);
        context.translate(-centerX, -centerY);
        j = [right, top, left, computed];
        drawText(j, context);
        if (myApp.isEnableMapGrid) {
            draw(j, context);
        }
        c = 0;
        for (; c < siblings.length; c++) {
            //siblings[c].s(context);
			//console.log(siblings[c]);
            //renderCells++;
        }
        c = 0;
        for (; c < list.length; c++) {
            list[c].s(context);
            /*if (window.drawTime > window.maxDrawTime) {
                break;
            }*
            renderCells++;*/
        }
		// Aros al rededor del jugador
        if (data.length && myApp.isEnableSplitInd) {
            context.globalAlpha = 0.7;
            pos = ~~Math.min(5 / scale, 50);
            context.lineWidth = pos;
            c = [];
            j = 0;
            for (; j < data.length; j++) {
                c.push({
                    x: data[j].x,
                    y: data[j].y,
                    size: data[j].size
                });
            }
            c.sort(function(a, b) {
                return a.size - b.size;
            });
            j = 0;
            for (; j < arr.length; j++) {
                var radius = arr[j].size * arr[j].size;
                var i = 0;
                for (; i < c.length; i++) {
                    var r = c[i].size * c[i].size;
                    var g = Math.sqrt(Math.pow(c[i].x - arr[j].x, 2) + Math.pow(c[i].y - arr[j].y, 2));
                    var ml = c[i].size + 655;
                    var b = arr[j].size + 655;
                    if (4 >= c.length && (0.375 * r * 0.37 > radius && 2 * ml - 10 > g)) {
                        arr[j].type = 4;
                        break;
                    }
                    if (8 >= c.length && (0.37 * r > radius && ml > g)) {
                        arr[j].type = 2;
                        break;
                    }
                    if (0.73 * r > radius && ml > g) {
                        arr[j].type = 1;
                        break;
                    }
                    if (0.37 * radius > r && b > g) {
                        arr[j].type = -2;
                        break;
                    }
                    if (0.73 * radius > r && b > g) {
                        arr[j].type = -1;
                        break;
                    }
                }
            }
            c = 0;
            for (; c < items.length; c++) {
                context.strokeStyle = items[c].color;
                context.beginPath();
                j = 0;
                for (; j < arr.length; j++) {
                    if (arr[j].type) {
                        if (arr[j].type == items[c].type) {
                            radius = arr[j].size + pos + 8 + 2 / scale;
                            context.moveTo(arr[j].x + radius, arr[j].y);
                            context.arc(arr[j].x, arr[j].y, radius, 0, PIx2, false);
                        }
                    }
                }
                context.stroke();
            }
        }
		
        if (arr = [], Xe) {
            node = (3 * node + fragment) / 4;
            n = (3 * n + m) / 4;
            context.save();
            context.strokeStyle = "#FFAAAA";
            context.lineWidth = 10;
            context.lineCap = "round";
            context.lineJoin = "round";
            context.globalAlpha = 0.5;
            context.beginPath();
            c = 0;
            for (; c < data.length; c++) {
                context.moveTo(data[c].x, data[c].y);
                context.lineTo(node, n);
            }
            context.stroke();
            context.restore();
        }
        context.restore();
        if (":teams" == index) {
            if (img) {
                if (img.width) {
                    context.drawImage(img, width - img.width - 10, 10);
                }
            }
        }
        closingAnimationTime = Math.max(closingAnimationTime, pick());
        diff = Date.now() - diff;
        if (diff > 1E3 / 60) {
            resolutionScale -= 0.01;
        } else {
            if (1E3 / 65 > diff) {
                resolutionScale += 0.01;
            }
        }
        if (0.4 > resolutionScale) resolutionScale = 0.4;
        if (resolutionScale > 1) resolutionScale = 1;
        diff = max - aux;
        if (!handler() || (to || from)) {
            newEnd += diff / 2E3;
            if (newEnd > 1) newEnd = 1;
        } else {
            newEnd -= diff / 300;
            if (0 > newEnd) newEnd = 0;
        }
        gSelfMass = pick() / 100;
        aux = max;
        /*var renderStop = +new Date();
        var renderDiff = renderStop - renderStart;
        window.netUpdate = renderStop - window.lastPacketTime;
        // At the end of the draw cycle, check if we hit max draw time
        if (netUpdate > 300) {
            if (!window.skipNetworkLoss) window.skipNetworkLoss = 1;
        } else window.skipNetworkLoss = 0;
        if (window.drawTime > window.maxDrawTime) {
            window.skipDraw++;
            // Every 10 draw cycles we have a problem
            if (window.skipDraw > 10) {
                window.skipDraw = 0;
                // Display a user notification
                // Increase max draw time by 10ms
                window.maxDrawTime += 10;
                // Update user interface bar
            }
        }*/
    }

    function redraw() {
        if (myApp.isEnableGridline) {
            context.save();
            context.strokeStyle = color ? "#AAAAAA" : "#000000";
            context.globalAlpha = 0.2 * scale;
            context.beginPath();
            var x = width / scale;
            var y = height / scale;
            var bounds = (-centerX + x / 2) % 50;
            for (; x > bounds; bounds += 50) { // Pinta las lÃ­neas verticales
                context.moveTo(bounds * scale - 0.5, 0);
                context.lineTo(bounds * scale - 0.5, y * scale);
            }
            bounds = (-centerY + y / 2) % 50;
            for (; y > bounds; bounds += 50) { // Pinta las lÃ­neas horizontales
                context.moveTo(0, bounds * scale - 0.5);
                context.lineTo(x * scale, bounds * scale - 0.5);
            }
            context.stroke();
            context.restore();
        }
    }

    function pick() {
        var result = 0;
        var i = 0;
        for (; i < data.length; i++) {
            result += data[i].m * data[i].m;
        }
        return result;
    }

    function create() {
        if (img = null, (null != angles || 0 != users.length) && (null != angles || oldStatus)) {
            img = document.createElement("canvas");
            var ctx = img.getContext("2d");
            var i = 60;
            i = null == angles ? i + 24 * users.length : i + 180;
            var d = Math.min(200, 0.3 * width) / 200;
            if (img.width = 200 * d, img.height = i * d, ctx.scale(d, d), ctx.globalAlpha = 0.4, ctx.fillStyle = "#000000", ctx.fillRect(0, 0, 200, i), ctx.globalAlpha = 1, ctx.fillStyle = "#FFFFFF", d = _("leaderboard"), ctx.font = "30px Ubuntu", ctx.fillText(d, 100 - ctx.measureText(d).width / 2, 40), null == angles) {
                ctx.font = "20px Ubuntu";
                i = 0;
                for (; i < users.length; ++i) {
                    d = users[i].name || _("unnamed_cell");
                    if (!oldStatus) {
                        d = _("unnamed_cell");
                    }
                    if (-1 != result.indexOf(users[i].id)) {
                        if (data[0].name) {
                            d = data[0].name;
                        }
                        ctx.fillStyle = "#FFAAAA";
                    } else {
                        ctx.fillStyle = "#FFFFFF";
                    }
                    d = i + 1 + ". " + d;
                    ctx.fillText(d, 100 - ctx.measureText(d).width / 2, 70 + 24 * i);
                }
            } else {
                i = d = 0;
                for (; i < angles.length; ++i) {
                    var piBy2 = d + angles[i] * Math.PI * 2;
                    ctx.fillStyle = cs[i + 1];
                    ctx.beginPath();
                    ctx.moveTo(100, 140);
                    ctx.arc(100, 140, 80, d, piBy2, false);
                    ctx.fill();
                    d = piBy2;
                }
            }
        }
    }

    function Player(opt_vars, x, y, opt_size, b) {
        this.P = opt_vars;
        this.x = x;
        this.y = y;
        this.g = opt_size;
        this.b = b;
    }

    function set(value, x, y, size, color, ms) {
        this.id = value;
        this.o = this.x = x;
        this.p = this.y = y;
        this.n = this.size = size;
        this.color = color;
        this.a = [];
        this.Q();
        this.t(ms);
    }

    function flush(count) {
        count = count.toString(16);
        for (; 6 > count.length;) {
            count = "0" + count;
        }
        return "#" + count;
    }

    function module(moduleNames, moduleDefinition, name, radius) {
        if (moduleNames) {
            this.q = moduleNames;
        }
        if (moduleDefinition) {
            this.M = moduleDefinition;
        }
        this.O = !!name;
        if (radius) {
            this.r = radius;
        }
    }

    function shuffle(arr) {
        var tmp1;
        var rnd;
        var total = arr.length;
        for (; total > 0;) {
            rnd = Math.floor(Math.random() * total);
            total--;
            tmp1 = arr[total];
            arr[total] = arr[rnd];
            arr[rnd] = tmp1;
        }
    }

    function drawText(g, ctx) {
        ctx.save();
        ctx.beginPath();
        ctx.strokeStyle = $("#borderColor").minicolors("value");
        var bw = ctx.lineWidth = Number(myApp.getBorderSize());
        ctx.strokeRect(g[0] - bw / 2, g[1] - bw / 2, g[2] - g[0] + bw, g[3] - g[1] + bw);
        ctx.restore();
    }

    function draw(t, ctx) {
        var x = Math.round(t[0]) + 40;
        var y = Math.round(t[1]) + 40;
        var second = "ABCDEFGHIJKLMNOPQRSTUVWXYZ".split("");
        var barWidth = (Math.round(t[2]) - 40 - x) / 5;
        var h = (Math.round(t[3]) - 40 - y) / 5;
        ctx.save();
        ctx.beginPath();
        ctx.lineWidth = 20;
        ctx.textAlign = "center";
        ctx.textBaseline = "middle";
        ctx.font = 0.6 * barWidth + "px Ubuntu";
        ctx.fillStyle = "#1A1A1A";
        var j = 0;
        for (; 5 > j; j++) {
            var i = 0;
            for (; 5 > i; i++) {
                ctx.fillText(second[j] + (i + 1), x + barWidth * i + barWidth / 2, y + h * j + h / 2);
            }
        }
        ctx.lineWidth = 100;
        ctx.strokeStyle = "#1A1A1A";
        j = 0;
        for (; 5 > j; j++) {
            i = 0;
            for (; 5 > i; i++) {
                ctx.strokeRect(x + barWidth * i, y + h * j, barWidth, h);
            }
        }
        ctx.stroke();
        ctx.restore();
    }

    function callback(href) {
        if (self.history) {
            if (self.history.replaceState) {
                self.history.replaceState({}, self.document.title, href);
            }
        }
    }

    function setData(node, data) {
        var o = -1 != result.indexOf(node.id);
        var n = -1 != result.indexOf(data.id);
        var i = 30 > data.size;
        if (o) {
            if (i) {
                ++pauseText;
            }
        }
        if (!i) {
            if (o) {
                if (!n) {
                    ++path;
                }
            }
        }
    }

    function fill(i) {
        i = ~~i;
        var lineNumber = (i % 60).toString();
        return i = (~~(i / 60)).toString(), 2 > lineNumber.length && (lineNumber = "0" + lineNumber), i + ":" + lineNumber;
    }

    function endsWith() {
        if (null == users) {
            return 0;
        }
        var i = 0;
        for (; i < users.length; ++i) {
            if (-1 != result.indexOf(users[i].id)) {
                return i + 1;
            }
        }
        return 0;
    }
    //window.maxDrawTime = 50;
    //window.skipDraw = 0;

    function DrawPolyline() {
        jQuery(".stats-food-eaten").text(pauseText);
        jQuery(".stats-time-alive").text(fill((far - near) / 1E3));
        jQuery(".stats-leaderboard-time").text(fill(name));
        jQuery(".stats-highest-mass").text(~~(closingAnimationTime / 100));
        jQuery(".stats-cells-eaten").text(path);
        jQuery(".stats-top-position").text(0 == count ? ":(" : count);
        var h = document.getElementById("statsGraph");
        if (h) {
            var ctx = h.getContext("2d");
            var width = h.width;
            if (h = h.height, ctx.clearRect(0, 0, width, h), 2 < a.length) {
                var n = 200;
                var i = 0;
                for (; i < a.length; i++) {
                    n = Math.max(a[i], n);
                }
                ctx.lineWidth = 3;
                ctx.lineCap = "round";
                ctx.lineJoin = "round";
                ctx.strokeStyle = col;
                ctx.fillStyle = col;
                ctx.beginPath();
                ctx.moveTo(0, h - a[0] / n * (h - 10) + 10);
                i = 1;
                for (; i < a.length; i += Math.max(~~(a.length / width), 1)) {
                    var x = i / (a.length - 1) * width;
                    var r = [];
                    var offset = -20;
                    for (; 20 >= offset; ++offset) {
                        if (!(0 > i + offset)) {
                            if (!(i + offset >= a.length)) {
                                r.push(a[i + offset]);
                            }
                        }
                    }
                    r = r.reduce(function(far, near) {
                        return far + near;
                    }) / r.length / n;
                    ctx.lineTo(x, h - r * (h - 10) + 10);
                }
                ctx.stroke();
                ctx.globalAlpha = 0.5;
                ctx.lineTo(width, h);
                ctx.lineTo(0, h);
                ctx.fill();
                ctx.globalAlpha = 1;
            }
        }
    }
    var simpleExpected = {
        context: function() {
            return g_context;
        },
        playerCellIds: function() {
            return g_playerCellIds;
        },
        playerCells: function() {
            return data;
        },
        cellsById: function() {
            return g_cellsById;
        },
        cells: function() {
            return g_cells;
        }
    };
    if (socket.on("playerUpdated", function(p) {
            if ("join" == p.action || "spectate" == p.action) {
                if (0 < simpleExpected.playerCells().length) {
                    conn.emit("playerUpdated", bind("update"));
                }
            }
            if (p.identifier) {
                playerDetailsByIdentifier[p.identifier] = p;
                playerDetailsByNick[p.nick] = p;
            }
        }), self.moveTo = function(lab, dragging) {
            if (lab) {
                if (dragging) {
                    myApp.isStopMovement = true;
                }
            }
        }, self.setPosition = function(p, index) {
            if (handler()) {
                var buf = encode(13);
                buf.setUint8(0, 16);
                buf.setInt32(1, p, true);
                buf.setInt32(5, index, true);
                buf.setUint32(9, 0, true);
                cb(buf);
            }
        }, window.handleQuickW = function() {
            if ($("#overview").is(":visible") || $('.chat-input').is(':focus')) return;
            if (myApp.autoW) {
                var buf = encode(1);
                buf.setUint8(0, 21);
                cb(buf);
                setTimeout(handleQuickW, 142);
            }
        }, !self.wairioNoInit) {
        var ee = "https:" == self.location.protocol;
        if (ee && -1 == self.location.search.indexOf("fb")) {
            self.location.href = "http://wair.io/";
        } else {
            var cv;
            var context;
            var cnv;
            var width;
            var height;
            var _root = null;
            var ws = null;
            var centerX = 0;
            var centerY = 0;
            var result = [];
            var data = [];
            window.queue = {};
            var list = [];
            var siblings = [];
            var users = [];
            var x = 0;
            var y = 0;
            var minX = -1;
            var t = -1;
            var target = 0;
            var max = 0;
            var aux = 0;
            var b = null;
            var right = -7071.067811865476;
            var top = -7071.06781186547;
            var left = 7071.067811865476;
            var computed = 7071.067811865476;
            var layers = 0;
            var dependencies = 0;
            var stack = 0;
            var before = 0;
            var scale = 1;
            var value = null;
            var error = true;
            var oldStatus = true;
            var doneResults = false;
            var Ee = false;
            var closingAnimationTime = 0;
            var color = 1;
            var $timeout = false;
            var chunk = centerX = ~~((right + left) / 2);
            var loc = centerY = ~~((top + computed) / 2);
            var crashed = 1;
            var index = "";
            var angles = null;
            var Ze = false;
            var Xe = false;
            var fragment = 0;
            var m = 0;
            var node = 0;
            var n = 0;
            var compassResult = 0;
            var cs = ["#333333", "#FF3333", "#33FF33", "#3333FF"];
            var dest = false;
            var matchEnd = false;
            var min = 0;
            var text = 1;
            var newEnd = 1;
            var to = false;
            var last = 0;
            var dst = {};
            var c = "";
            var deep = 0;
            var arr = [];
            var arr2 = [];
            var PIx2 = 2 * Math.PI;
            var column = 0;
            var clockseq = 0;
            var fx = 0;
            var _clockseq = 0;
            var type = 0;
            var positions = [];
            var items = [ { type: 1, color: "#d3d3d3" }, { type: 2, color: "#76FF03" }, { type: 4, color: "#2196F3" }, { type: -1, color: "#FF9800" }, { type: -2, color: "#FD0000" }, { type: -4, color: "white"} ];
            setInterval(function() {
                _clockseq = clockseq;
                clockseq = 0;
                type = fx;
                fx = 0;
            }, 1E3);
            (function() {
                var params = self.location.search;
                if ("?" == params.charAt(0)) {
                    params = params.slice(1);
                }
                params = params.split("&");
                var i = 0;
                for (; i < params.length; i++) {
                    var src = params[i].split("=");
                    dst[src[0]] = src[1];
                }
            })();
            var test_canvas = document.createElement("canvas");
            if ("undefined" == typeof console || ("undefined" == typeof DataView || ("undefined" == typeof WebSocket || (null == test_canvas || (null == test_canvas.getContext || null == self.localStorage))))) {
                alert("You browser does not support this game, we recommend you to use Firefox to play this");
            } else {
                var old = null;
                self.setNick = function(v) {
                    if (self.ga) {
                        self.ga("send", "event", "Nick", v.toLowerCase());
                    }
                    _init();
                    b = v;
                    writeUTFBytes();
                    closingAnimationTime = 0;
                    setLocalStorage("nick", v);
                    myApp.newGame();
                    announcementSent = false;
                    resolve();
                };
                self.setSkins = function(err) {
                    error = err;
                };
                self.setNames = function(newStatus) {
                    oldStatus = newStatus;
                };
                self.setDarkTheme = function(newColor) {
                    color = newColor;
                };
                self.setColors = function(data) {
                    doneResults = data;
                };
                self.setShowMass = function(_$timeout_) {
                    $timeout = _$timeout_;
                };
                self.getCurrentX = function() {
                    return data.length ? centerX - (left - 7071.067811865476) : "";
                };
                self.getCurrentY = function() {
                    return data.length ? centerY - (computed - 7071.067811865476) : "";
                };
                self.getTop1X = function() {
                    return chunk;
                };
                self.getTop1Y = function() {
                    return loc;
                };
                self.getLengthX = function() {
                    return 14142.135623730952;
                };
                self.getLengthY = function() {
                    return 14142.135623730952;
                };
                self.getLB = function() {
                    return users;
                };
                self.getSelfIDs = function() {
                    return result;
                };
                self.getCell = function() {
                    return data;
                };
                self.getHighestScore = function() {
                    return closingAnimationTime;
                };
                self.quickSpace = function() {
                    if ($("#overview").is(":visible") || $('.chat-input').is(':focus')) return;
                    if (0 != data.length) {
                        emit(17);
                        setTimeout(function() {
                            emit(17);
                        }, 40);
                        setTimeout(function() {
                            emit(17);
                        }, 80);
                        setTimeout(function() {
                            emit(17);
                        }, 120);
                    }
                };
                self.doubleSpace = function() {
                    if ($("#overview").is(":visible") || $('.chat-input').is(':focus')) return;
                    setTimeout(function() {
                        emit(17);
                    }, 50);
                    setTimeout(function() {
                        emit(17);
                    }, 100);
                };
                self.getFPS = function() {
                    return deep;
                };
                self.getPacketIO = function() {
                    return [_clockseq, type];
                };
                self.spectate = function() {
                    isJoinedGame = false;
                    spectateMode = true;
                    b = null;
                    emit(1);
                    _init();
                    myApp.spectate(data);
                    var cb = bind("spectate");
                    conn.emit("playerEntered", cb);
                };
                self.setZoomLevel = function(textAlt) {
                    text = textAlt;
                };
                self.isFreeSpec = function() {
                    return myApp.isSpectating && 0.25 === column;
                };
                self.setAcid = function(vec) {
                    dest = vec;
                };
                if (null != self.localStorage) {
                    if (null == self.localStorage.AB9) {
                        self.localStorage.AB9 = 0 + ~~(100 * Math.random());
                    }
                    compassResult = +self.localStorage.AB9;
                    self.ABGroup = compassResult;
                }
                var save = null;
                self.connect = open;//self.connect = open; //
                var backoff = 500;
                var tref = null;
                var millis = 0;
                var maxX = -1;
                var t1 = -1;
                var img = null;
                var resolutionScale = 1;
                var which = function() {
                    Date.now();
                    var diff = 0;
                    var aux = Date.now();
                    return function() {
                        self.requestAnimationFrame(which);
                        var max = Date.now();
                        if (myApp.isShowFPS) {
                            if (diff > 1E3) {
                                aux = max;
                                diff = 0;
                                deep = target;
                                target = 0;
                            } else {
                                diff = max - aux;
                            }
                        }
                        if (!handler() || 240 > Date.now() - min) render();
                        throttledUpdate();
                    };
                }();
                var results = {};
                var numbers = "poland;usa;china;russia;canada;australia;spain;brazil;germany;ukraine;france;sweden;chaplin;north korea;south korea;japan;united kingdom;earth;greece;latvia;lithuania;estonia;finland;norway;cia;maldivas;austria;nigeria;reddit;yaranaika;confederate;9gag;indiana;4chan;italy;bulgaria;tumblr;2ch.hk;hong kong;portugal;jamaica;german empire;mexico;sanik;switzerland;croatia;chile;indonesia;bangladesh;thailand;iran;iraq;peru;moon;botswana;bosnia;netherlands;european union;taiwan;pakistan;hungary;satanist;qing dynasty;matriarchy;patriarchy;feminism;ireland;texas;facepunch;prodota;cambodia;steam;piccolo;ea;india;kc;denmark;quebec;ayy lmao;sealand;bait;tsarist russia;origin;vinesauce;stalin;belgium;luxembourg;stussy;prussia;8ch;argentina;scotland;sir;romania;belarus;wojak;doge;nasa;byzantium;imperial japan;french kingdom;somalia;turkey;mars;pokerface;8;irs;receita federal;facebook;putin;merkel;tsipras;obama;kim jong-un;dilma;hollande;berlusconi;cameron;clinton;hillary;venezuela;blatter;chavez;cuba;fidel;merkel;palin;queen;boris;bush;trump".split(";");
                var reserved = "8;nasa;putin;merkel;tsipras;obama;kim jong-un;dilma;hollande;berlusconi;cameron;clinton;hillary;blatter;chavez;fidel;merkel;palin;queen;boris;bush;trump".split(";");
                var images = {};
                Player.prototype = {
                    P: null,
                    x: 0,
                    y: 0,
                    g: 0,
                    b: 0
                };
                set.prototype = {
                    id: 0,
                    a: null,
                    name: null,
                    k: null,
                    I: null,
                    x: 0,
                    y: 0,
                    size: 0,
                    o: 0,
                    p: 0,
                    n: 0,
                    C: 0,
                    D: 0,
                    m: 0,
                    T: 0,
                    K: 0,
                    W: 0,
                    A: false,
                    f: false,
                    j: false,
                    L: true,
                    S: 0,
                    V: null,
                    R: function() {
                        var i;
                        i = 0;
                        for (; i < list.length; i++) {
                            if (list[i] == this) {
                                list.splice(i, 1);
                                break;
                            }
                        }
                        delete queue[this.id];
                        i = data.indexOf(this);
                        if (-1 != i) {
                            Ee = true;
                            data.splice(i, 1);
                        }
                        i = result.indexOf(this.id);
                        if (-1 != i) {
                            result.splice(i, 1);
                        }
                        this.A = true;
                        if (this.size > 21) {
                            siblings.push(this);
                        }
                    },
                    i: function() {
                        if (this.f) {
                            return Math.max(~~(0.3 * this.m), 24);
                        } else {
                            var op = myApp.getNameMassScale();
                            return Math.max(~~(op * this.m), 24);
                        }
                    },
                    t: function(str) {
                        var directives = str.match(/\u0001([\u0002-\uffff]|[\u0002-\uffff]\uffff)$/g);
                        var a = 0;
                        if (directives) {
                            a = directives[0].split("\u0001")[1];
                            if (1 < a.length) {
                                this.img = a.charCodeAt(0) + 65534;
                            }
                        }
                        if (this.name = str) {
                            if (null == this.k) {
                                this.k = new module(this.i(), "#FFFFFF", true, "#000000");
                                this.k.v = Math.ceil(10 * scale) / 10;
                            } else {
                                this.k.G(this.i());
                            }
                            this.k.u(this.name);
                        }
                    },
                    Q: function() {
                        var a = this.B();
                        for (; this.a.length > a;) {
                            var data = ~~(Math.random() * this.a.length);
                            this.a.splice(data, 1);
                        }
                        if (0 == this.a.length) {
                            if (a > 0) {
                                this.a.push(new Player(this, this.x, this.y, this.size, Math.random() - 0.5));
                            }
                        }
                        for (; this.a.length < a;) {
                            data = ~~(Math.random() * this.a.length);
                            data = this.a[data];
                            this.a.push(new Player(this, data.x, data.y, data.g, data.b));
                        }
                    },
                    B: function() {
                        var rh = 10;
                        if (20 > this.size) {
                            rh = 0;
                        }
                        if (this.f) {
                            rh = 30;
                        }
                        var height = this.size;
                        return this.f || (height *= scale), height *= resolutionScale, 32 & this.T && (height *= 0.25), ~~Math.max(height, rh);
                    },
					
					// Este es el efecto gelatina
                    da: function() {
                        this.Q();
                        var nodes = this.a;
                        var n = nodes.length;
                        var i = 0;
						//console.log("nodos: " + n);
						/* 
						* Cuando el efecto es agarplus, osea simpleDrawing, la cantidad de nodos siempre es 100 a veces 99, aunque me divida o no me divida.
						
						* Cuando es efecto gelatina, la cantidad de nodos varÃ­a. CuÃ¡nto mÃ¡s me divido la cantidad de nodos es menor, y cuando estoy unido es mayor. A parte, varÃ­a con el zoom. A mayor zoom, menos es la cantidad de nodos.
						*/
                        for (i = 0; i < n; ++i) {
                            var a = nodes[(i - 1 + n) % n].b;
                            var b = nodes[(i + 1) % n].b;
                            nodes[i].b += (Math.random() - 0.5) * (this.j ? 3 : 1);
                            nodes[i].b *= 0.7;
                            if (10 < nodes[i].b) {
                                nodes[i].b = 10;
                            }
                            if (-10 > nodes[i].b) {
                                nodes[i].b = -10;
                            }
                            nodes[i].b = (a + b + 8 * nodes[i].b) / 10;
                        }
                        var ELEMENT_NODE = this;
                        var sa = this.f ? 0 : (this.id / 1E3 + max / 1E4) % (2 * Math.PI);
                        i = 0;
                        for (; n > i; ++i) {
                            var g = nodes[i].g;
                            if (a = nodes[(i - 1 + n) % n].g, b = nodes[(i + 1) % n].g, 15 < this.size && (null != _root && (20 < this.size * scale && 0 < this.id))) {
                                var r = false;
                                var x = nodes[i].x;
                                var y = nodes[i].y;
                                _root.ea(x - 5, y - 5, 10, 10, function(node) {
                                    if (node.P != ELEMENT_NODE) {
                                        if (25 > (x - node.x) * (x - node.x) + (y - node.y) * (y - node.y)) {
                                            r = true;
                                        }
                                    }
                                });
                                if (!r) {
                                    if (nodes[i].x < right || (nodes[i].y < top || (nodes[i].x > left || nodes[i].y > computed))) {
                                        r = true;
                                    }
                                }
                                if (r) {
                                    if (0 < nodes[i].b) {
                                        nodes[i].b = 0;
                                    }
                                    --nodes[i].b;
                                }
                            }
                            g += nodes[i].b;
                            if (0 > g) {
                                g = 0;
                            }
                            g = this.j ? (19 * g + this.size) / 20 : (12 * g + this.size) / 13;
                            nodes[i].g = (a + b + 8 * g) / 10;
                            a = 2 * Math.PI / n;
                            b = this.a[i].g;
                            if (this.f) {
                                if (0 == i % 2) {
                                    b += 5;
                                }
                            }
                            nodes[i].x = this.x + Math.cos(a * i + sa) * b;
                            nodes[i].y = this.y + Math.sin(a * i + sa) * b;
                        }
                    },
                    J: function() {
                        if (0 >= this.id) {
                            return 1;
                        }
                        var p;
                        p = (max - this.K) / myApp.delayAnimation();
                        p = 0 > p ? 0 : p > 1 ? 1 : p;
                        var n = 0 > p ? 0 : p > 1 ? 1 : p;
                        if (this.i(), this.A && n >= 1) {
                            var index = siblings.indexOf(this);
                            if (-1 != index) {
                                siblings.splice(index, 1);
                            }
                        }
                        return this.x = p * (this.C - this.o) + this.o, this.y = p * (this.D - this.p) + this.p, this.size = n * (this.m - this.n) + this.n, n;
                    },
                    H: function() {
                        return 0 >= this.id ? true : this.x + this.size + 40 < centerX - width / 2 / scale || (this.y + this.size + 40 < centerY - height / 2 / scale || (this.x - this.size - 40 > centerX + width / 2 / scale || this.y - this.size - 40 > centerY + height / 2 / scale)) ? false : true;
                    },
                    getStrokeColor: function() {
                        var factor = myApp.getCellColor();
                        var digits = (~~(parseInt(this.color.substr(1, 2), 16) * factor)).toString(16);
                        var result = (~~(parseInt(this.color.substr(3, 2), 16) * factor)).toString(16);
                        var indent = (~~(parseInt(this.color.substr(5, 2), 16) * factor)).toString(16);
                        return 1 == digits.length && (digits = "0" + digits), 1 == result.length && (result = "0" + result), 1 == indent.length && (indent = "0" + indent), "#" + digits + result + indent;
                    },
                    s: function(ctx) {
                        var drawStart = +new Date();
                        if (this.H()) {
                            var f = myApp.isEnableSimpleDrawing;
                            if (this.size < 21) {
                                if (!myApp.isEnableHideFood) {
                                    if (myApp.isSameColorFood) {
                                        ctx.beginPath();
                                        ctx.fillStyle = $("#pelletColor").minicolors("value");
                                        if (myApp.isEnabledSquareFood) {
                                            context.fillRect(this.x - this.size, this.y - this.size, this.size * 2 + 10, this.size * 2 + 10);
                                        } else {
                                            ctx.arc(this.x, this.y, this.size + 5, 0, 2 * Math.PI, false);
                                        }
                                        ctx.fill();
                                    } else {
                                        ctx.beginPath();
                                        //ctx.fillStyle = this.color;
                                        ctx.fillStyle = this.getStrokeColor();
                                        //ctx.arc(this.x, this.y, this.size + 5, 0, 2 * Math.PI, false);
                                        ctx.arc(this.x, this.y, this.size, 0, 2 * Math.PI, false);
                                        ctx.fill();
                                    }
                                }
                            } else {
                                ++this.S;
                                var y_position = 0 < this.id && (!this.f && (!this.j && 0.4 > scale));
                                if (5 > this.B() && (0 < this.id && (y_position = true)), this.L && !y_position) {
                                    var i = 0;
                                    for (; i < this.a.length; i++) {
                                        this.a[i].g = this.size;
                                    }
                                }
                                this.L = y_position;
                                ctx.save();
                                this.W = max;
                                i = this.J();
                                if (this.A) {
                                    ctx.globalAlpha *= 1 - i;
                                }
                                ctx.lineWidth = 10;
                                ctx.lineCap = "round";
                                ctx.lineJoin = this.f ? "miter" : "round";
                                i = !this.f && (0 < this.id && (21 <= this.size && !this.j)) ? true : false;
                                var v;
                                var isHideSelfName = false;
                                var x = null;
                                if (v = this.name + this.color, v = v in playerDetailsByIdentifier ? playerDetailsByIdentifier[v] : void 0, i) {
                                    if (myApp.isTransparentCell) {
                                        //ctx.globalAlpha = theoObjects.blobsTransparency;
                                        ctx.globalAlpha = 0.8;
                                    }
                                    var c = 0;
                                    for (; c < result.length; c++) {
                                        if (this.id === result[c]) {
                                            isHideSelfName = true;
                                        }
                                    }
                                    if (isHideSelfName) {
                                        if (myApp.isEnableCursorLine) {
                                            ctx.save();

                                            if (myApp.emphasisCursorLine) {
                                                ctx.lineWidth = 10;
                                                ctx.strokeStyle = $("#emphasisCursorLine").minicolors("value");
                                            } else {
                                                ctx.lineWidth = 2;
                                                ctx.strokeStyle = $("#mouseLineColor").minicolors("value");
                                            }
                                            ctx.lineCap = "round";
                                            ctx.lineJoin = "round";
                                            ctx.globalAlpha = 0.8;
                                            ctx.beginPath();
                                            ctx.moveTo(this.x, this.y);
                                            ctx.lineTo(minX, t);
                                            ctx.stroke();
                                            ctx.restore();
                                        }
                                        if (myApp.isEnableAttackRange) {
                                            ctx.beginPath();
                                            ctx.strokeStyle = color ? "white" : "black";
                                            ctx.arc(this.x, this.y, this.size + myApp.attackRangeRadius, 0, 2 * Math.PI, false);
                                            ctx.stroke();
                                            ctx.closePath();
                                        }
                                        if (myApp.isEnableCustomSkin) {
                                            // nodeList[0][5] <- skinURL
                                            x = myApp.getSkinImage(nodeList[0][5]);
                                            //ctx.globalAlpha = theoObjects.skinsTransparency;
                                        }
                                    }
                                }
                                if (doneResults ? (ctx.fillStyle = "#FFFFFF", ctx.strokeStyle = "#AAAAAA") : (ctx.fillStyle = this.getStrokeColor(), ctx.strokeStyle = this.getStrokeColor()), f && (this.f && (ctx.fillStyle = $("#virusColor").minicolors("value"), ctx.strokeStyle = $("#virusStrokeColor").minicolors("value"))), f || y_position) {
                                    ctx.beginPath();
                                    if (myApp.isEnabledSquareCell) {
                                        ctx.fillRect(this.x - this.size, this.y - this.size, 2 * this.size, 2 * this.size);
                                    } else {
                                        ctx.arc(this.x, this.y, this.size + 5, 0, 2 * Math.PI, false);
                                    }
                                    if (myApp.isEnableSplitInd) {
                                        if (i) {
                                            if (!isHideSelfName) {
                                                if (this.name || 38 < this.size) {
                                                    arr.push({
                                                        x: this.x,
                                                        y: this.y,
                                                        size: this.size
                                                    });
                                                }
                                            }
                                        }
                                    }


                                    /**************/
                                    if (i) {
                                        if (!isHideSelfName) {
                                            if (this.name || 38 < this.size) {
                                                arr2.push({
                                                    x: this.x,
                                                    y: this.y,
                                                    size: this.size,
                                                    name: this.name
                                                });
                                            }
                                        }
                                    }
                                    /*************/
                                } else {
                                    // vanilla
                                    this.da();
                                    ctx.beginPath();
                                    var n = this.B();
                                    ctx.moveTo(this.a[0].x, this.a[0].y);
                                    i = 1;
                                    for (; i <= n; ++i) {
                                        c = i % n;
                                            ctx.lineTo(this.a[c].x, this.a[c].y);
                                    }
                                }
                                if (ctx.closePath(), i = this.name.toLowerCase(), 
                                
                                c = this.img ? "http://upload.happyfor.me/getimg.php?id=" + this.img + "&_t=" + Math.random() : "skins/" + i + ".png", //c = this.img ? "http://upload.happyfor.me/getimg.php?id=" + this.img + "&_t=" + Math.random() : "skins/" + i + ".png", 
                                

                                x || (this.j || (!error && !myApp.isEnableOtherSkinSupport || ":teams" == index)) ? n = null : (n = this.V, null == n ? n = null : ":" == n[0] ? (images.hasOwnProperty(n) || (images[n] = new Image, images[n].src = n.slice(1)), n = 0 != images[n].width && images[n].complete ? images[n] : null) : n = null, n || (-1 !=
                                        numbers.indexOf(i) && error || this.img ? ($.hasOwnProperty(i) || ($[i] = new Image, $[i].src = c), n = 0 != $[i].width && $[i].complete ? $[i] : null) : n = null)), c = n, y_position || f && (this.f && ctx.stroke()), ctx.fill(), 

                                    myApp.isEnableCustomSkin && (n = null, x = false, v && (x = v.url), 
                                        x && (results.hasOwnProperty(x) || (v = new Image, v.src = x, results[x] = v), results[x].width && (results[x].complete && (n = results[x]))), c = n, null != c)) {
                                    var size = Math.min(c.width, c.height);
                                    var startX = (c.width - size) / 2;
                                    var offsetY = (c.height - size) / 2;
                                    var y = this.size + 5;
                                }
                                if (null != c && (
                                    ctx.save(), 

                                    myApp.isEnabledSquareCell ? ctx.drawImage(c, startX + size / 4, offsetY + size / 4, size * 0.5, size * 0.5, this.x - y, this.y - y, 2 * y, 2 * y) : (ctx.clip(), ctx.drawImage(c, startX, offsetY, size, size, this.x - y, this.y - y, 2 * y, 2 * y)),

                                    ctx.restore()),

                                     f || ((doneResults || 21 < this.size) && (y_position || (ctx.strokeStyle = "#000000", ctx.globalAlpha *= 0.1, ctx.stroke())), ctx.globalAlpha = 1), n = -1 != data.indexOf(this), y_position = ~~this.y, f = this.f || (315 < this.size || 18 < this.size * scale), !(isHideSelfName && myApp.isHideSelfName || myApp.isAutoHideName && !f) && (0 != this.id &&
                                        ((oldStatus || n) && (this.name && (this.k && (null == c || -1 == reserved.indexOf(i))))))) {
                                    c = this.k;
                                    c.u(this.name);
                                    c.G(this.i() / 0.9);
                                    i = 0 >= this.id ? 1 : Math.ceil(10 * scale) / 10;
                                    c.U(i);
                                    c = c.F();
                                    var glockBottomWidth = ~~(c.width / i);
                                    var sh = ~~(c.height / i);
                                    ctx.drawImage(c, ~~this.x - ~~(glockBottomWidth / 2), y_position - ~~(sh / 2), glockBottomWidth, sh);
                                    y_position += c.height / 2 / i + 4;
                                }
                                if (!myApp.isAutoHideMass || f) {
                                    if (myApp.isEnableShowAllMass) {
                                        if (0 < this.id) {
                                            if ($timeout) {
                                                if (38 < this.size) {
                                                    if (null == this.I) {
                                                        this.I = new module(this.i() / 2, "#FFFFFF", true, "#000000");
                                                    }
                                                    n = this.I;
                                                    n.G(this.i() / 0.8);
                                                    n.u(~~(this.size * this.size / 100));
                                                    i = Math.ceil(10 * scale) / 10;
                                                    n.U(i);
                                                    c = n.F(this.f);
                                                    glockBottomWidth = ~~(c.width / i);
                                                    sh = ~~(c.height / i);
                                                    if (this.f) ctx.drawImage(c, ~~this.x - ~~(glockBottomWidth / 2), y_position - ~~(sh / 2), glockBottomWidth, sh);
                                                    else ctx.drawImage(c, ~~this.x - ~~(glockBottomWidth / 2), y_position - ~~(sh / 3), glockBottomWidth, sh);
                                                }
                                            }
                                        }
                                    }
                                }
                                ctx.restore();
                            }
                        }
                        //var drawEnd = +new Date();
                        //var diff = drawEnd - drawStart;
                        //window.drawTime += diff;
                    }
                };
                module.prototype = {
                    w: "",
                    M: "#000000",
                    O: false,
                    r: "#000000",
                    q: 16,
                    l: null,
                    N: null,
                    h: false,
                    v: 1,
                    G: function(x) {
                        if (5 < Math.abs(x - this.q)) {
                            if (this.q != x) {
                                this.q = x;
                                this.h = true;
                            }
                        }
                    },
                    U: function(v) {
                        if (this.v != v) {
                            this.v = v;
                            this.h = true;
                        }
                    },
                    setStrokeColor: function(r) {
                        if (this.r != r) {
                            this.r = r;
                            this.h = true;
                        }
                    },
                    u: function(n) {
                        var w;
                        if (!isNaN(n)) {
                            if (!isNaN(this.w)) {
                                if (0 != this.w) {
                                    if (0 != n) {
                                        if (this.w != n) {
                                            if (0.012 > Math.abs((n - this.w) / this.w)) {
                                                w = this.w;
                                                this.w = n;
                                            }
                                        }
                                    }
                                }
                            }
                        }
                        if (n != this.w) {
                            this.w = n;
                            this.h = true;
                        }
                        if (w) this.w = w;
                    },
                    F: function(isVirus) {
                        if (null == this.l && (this.l = document.createElement("canvas"), this.N = this.l.getContext("2d")), this.h) {
                            this.h = true;
                            size = this.l;
                            c = this.N;
                            line = this.w;
                            factor = this.v;
                            var y = isVirus ? this.q : this.q / 1.5;
                            if (isVirus) {
                                font = "bold 25px Ubuntu";
                            } else {
                                font = "bold " + (y * myApp.getNameMassScale()) + "px Ubuntu";
                            }
                            c.font = font;
                            var height = ~~(0.3 * y);
                            if (isVirus) {
                                line = ~~((200 - line) / 14);
                                factor *= 2.5;
                            } else {
                                if (!isNaN(parseInt(line))) {
                                    line = parseInt(line);
                                    if (myApp.isEnabledShortMass) {
                                        if (line > 999) line = String(Number((line / 1000).toFixed(1))) + "k";
                                    }
                                }
                            }
                            size.width = (c.measureText(line).width + 6) * factor;
                            size.height = (y + height) * factor;
                            c.font = font;
                            c.scale(factor, factor);
                            c.globalAlpha = 1;
                            //c.fillStyle = $("#fillTextColor").minicolors("value");
                            c.fillStyle = this.M;
                            if (myApp.isShowTextStrokeLine) {
                                c.lineWidth = Math.max(right * 0.12, 12);
                                //c.lineWidth = 7;
                                //c.strokeStyle = $("#strokeTextColor").minicolors("value");
                                c.strokeStyle = this.r;
                                if (this.O) c.strokeText(line, 3, y - height / 2);
                            }
                            c.fillText(line, 3, y - height / 2);
                        }
                        return this.l;
                    }
                };
                if (!Date.now) {
                    Date.now = function() {
                        return (new Date).getTime();
                    };
                }
                (function() {
                    var vendors = ["ms", "moz", "webkit", "o"];
                    var x = 0;
                    for (; x < vendors.length && !self.requestAnimationFrame; ++x) {
                        self.requestAnimationFrame = self[vendors[x] + "RequestAnimationFrame"];
                        self.cancelAnimationFrame = self[vendors[x] + "CancelAnimationFrame"] || self[vendors[x] + "CancelRequestAnimationFrame"];
                    }
                    if (!self.requestAnimationFrame) {
                        self.requestAnimationFrame = function(callback) {
                            return setTimeout(callback, 1E3 / 60);
                        };
                        self.cancelAnimationFrame = function(id) {
                            clearTimeout(id);
                        }; // suavidad
                    }
                })();
                var removeEventListener = function() {
                    var self = new set(0, 0, 0, 32, "#ED1C24", "");
                    var cnv = document.createElement("canvas");
                    cnv.width = 32;
                    cnv.height = 32;
                    var s = cnv.getContext("2d");
                    return function() {
                        if (0 < data.length) {
                            self.color = data[0].color;
                            self.t(data[0].name);
                        }
                        s.clearRect(0, 0, 32, 32);
                        s.save();
                        s.translate(16, 16);
                        s.scale(0.4, 0.4);
                        self.s(s);
                        s.restore();
                    };
                }();
                jQuery(function() {
                    removeEventListener();
                });
                var i = "loginCache3";
                jQuery(function() {
                    if (+self.localStorage.wannaLogin) {
                        if (self.localStorage[i]) {
                            var data = self.localStorage[i];
                            if ("string" == typeof data) {
                                data = JSON.parse(data);
                            }
                            if (Date.now() + 18E5 > data.expires) {
                                jQuery("#helloContainer").attr("data-logged-in", "0");
                            } else {
                                self.localStorage[i] = JSON.stringify(data);
                                jQuery(".agario-profile-name").text(data.name);
                                oncomplete();
                                jQuery("#helloContainer").attr("data-logged-in", "1");
                            }
                        }
                        if (self.localStorage.fbPictureCache) {
                            jQuery(".agario-profile-picture").attr("src", self.localStorage.fbPictureCache);
                        }
                    }
                });
                self.facebookLogin = function() {
                    self.localStorage.wannaLogin = 1;
                };
                self.fbAsyncInit = function() {
                    function reset() {
                        self.localStorage.wannaLogin = 1;
                        if (null == self.FB) {
                            alert("You seem to have something blocking Facebook on your browser, please check for any extensions");
                        } else {
                            self.FB.login(function(value) {
                            }, {
                                scope: "public_profile, email"
                            });
                        }
                    }
                    self.FB.init({
                        appId: "677505792353827",
                        cookie: true,
                        xfbml: true,
                        status: true,
                        version: "v2.2"
                    });
                    self.facebookLogin = reset;
                };
                self.logout = function() {
                    jQuery("#helloContainer").attr("data-logged-in", "0");
                    jQuery("#helloContainer").attr("data-has-account-data", "0");
                    delete self.localStorage.wannaLogin;
                    delete self.localStorage[i];
                    delete self.localStorage.fbPictureCache;
                    $("#button-spectate").prop("disabled", false);
                };
                var throttledUpdate = function() {
                    function render(d, map, str, size, data) {
                        var s = map.getContext("2d");
                        var len = map.width;
                        map = map.height;
                        d.color = data;
                        d.t(str);
                        d.size = size;
                        s.save();
                        s.translate(len / 2, map / 2);
                        d.s(s);
                        s.restore();
                    }
                    var data = new set(-1, 0, 0, 32, "#5bc0de", "");
                    var dir = new set(-1, 0, 0, 32, "#5bc0de", "");
                    var codeSegments = "#0791ff #5a07ff #ff07fe #ffa507 #ff0774 #077fff #3aff07 #ff07ed #07a8ff #ff076e #3fff07 #ff0734 #07ff20 #ff07a2 #ff8207 #07ff0e".split(" ");
                    var items = [];
                    var i = 0;
                    for (; i < codeSegments.length; ++i) {
                        var bisection = i / codeSegments.length * 12;
                        var radius = 30 * Math.sqrt(i / codeSegments.length);
                        items.push(new set(-1, Math.cos(bisection) * radius, Math.sin(bisection) * radius, 10, codeSegments[i], ""));
                    }
                    shuffle(items);
                    var map = document.createElement("canvas");
                    return map.getContext("2d"), map.width = map.height = 70, render(dir, map, "", 26, "#ebc0de"),
                        function() {
                            jQuery(".cell-spinner").filter(":visible").each(function() {
                                var body = jQuery(this);
                                var x = Date.now();
                                var width = this.width;
                                var height = this.height;
                                var context = this.getContext("2d");
                                context.clearRect(0, 0, width, height);
                                context.save();
                                context.translate(width / 2, height / 2);
                                var y = 0;
                                for (; 10 > y; ++y) {
                                    context.drawImage(map, (0.1 * x + 80 * y) % (width + 140) - width / 2 - 70 - 35, height / 2 * Math.sin((0.001 * x + y) % Math.PI * 2) - 35, 70, 70);
                                }
                                context.restore();
                                if (body = body.attr("data-itr")) {
                                    body = _(body);
                                }
                                render(data, this, body || "", +jQuery(this).attr("data-size"), "#5bc0de");
                            });
                            jQuery("#statsPellets").filter(":visible").each(function() {
                                jQuery(this);
                                var i = this.width;
                                var height = this.height;
                                this.getContext("2d").clearRect(0, 0, i, height);
                                i = 0;
                                for (; i < items.length; i++) {
                                    render(items[i], this, "", items[i].size, items[i].color);
                                }
                            });
                        };
                }();
                var a = [];
                var pauseText = 0;
                var col = "#000000";
                var from = false;
                var Bt = false;
                var near = 0;
                var far = 0;
                var name = 0;
                var path = 0;
                var count = 0;
                var connected = true;
                setInterval(function() {
                    if (Bt) {
                        a.push(pick() / 100);
                    }
                }, 1E3 / 60);
                setInterval(function() {
                    var tempCount = endsWith();
                    if (0 != tempCount) {
                        ++name;
                        if (0 == count) {
                            count = tempCount;
                        }
                        count = Math.min(count, tempCount);
                    }
                }, 1E3);
                self.closeStats = function() {
                    from = false;
                    focus(0);
                };
                self.setSkipStats = function(err) {
                    connected = !err;
                };
                jQuery(function() {
                    jQuery(init);
                });
            }
        }
    }
}(window, window.jQuery), 

myApp.afterGameLogicLoaded(), 


$(document).keydown(function(e) {
    if ("input" != e.target.tagName.toLowerCase() && "textarea" != e.target.tagName.toLowerCase() || 13 == e.keyCode) {
        var username = "";
        if (isValidHotKey(e) && (username = getPressedKey(e)), 18 == e.keyCode && e.preventDefault(), selectedHotkeyRow) {
            if (46 == e.keyCode) {
                e.preventDefault();
                selectedHotkeyRow.find(".hotkey").text(username);
            } else {
                if ("" != username) {
                    e.preventDefault();
                    var codeSegments = $(".hotkey");
                    var i = 0;
                    for (; i < codeSegments.length; i++) {
                        if ($(codeSegments[i]).text() == username) {
                            return;
                        }
                    }
                    selectedHotkeyRow.find(".hotkey").text(username);
                    selectedHotkeyRow.removeClass("table-row-selected");
                    selectedHotkeyRow = null;
                }
            }
        }
        if ("" != username) {
            if (hotkeyMapping[username]) {
                e.preventDefault();
                if (hotkeyConfig[hotkeyMapping[username]]) {
                    if (hotkeyConfig[hotkeyMapping[username]].keyDown) {
                        hotkeyConfig[hotkeyMapping[username]].keyDown();
                    }
                }
            }
        }
    }
}), 
$(document).keyup(function(e) {
    if ("input" != e.target.tagName.toLowerCase() && "textarea" != e.target.tagName.toLowerCase() || 13 == e.keyCode) {
        var rt = "";
        if (isValidHotKey(e)) {
            rt = getPressedKey(e);
        }
        if ("" != rt) {
            if (hotkeyMapping[rt]) {
                e.preventDefault();
                if (hotkeyConfig[hotkeyMapping[rt]]) {
                    if (hotkeyConfig[hotkeyMapping[rt]].keyUp) {
                        hotkeyConfig[hotkeyMapping[rt]].keyUp();
                    }
                }
            }
        }
    }
}), 

$("#hud").mousedown(function(e) {
    if (0 === e.button) {
        if (myApp.isEnableMouseW) {
            if ("input" != e.target.tagName.toLowerCase() || "textarea" != e.target.tagName.toLowerCase()) {
                myApp.autoW = true;
                handleQuickW();
                e.preventDefault();
            }
        }
    } else {
        if (2 === e.button) {
            $("#opt_chatbox").click();
        }
    }
}), 
$("#hud").mouseup(function(e) {
    if (0 === e.button) {
        if (myApp.isEnableMouseW) {
            if ("input" != e.target.tagName.toLowerCase()) {
                if ("textarea" != e.target.tagName.toLowerCase()) {
                    myApp.autoW = false;
                    e.preventDefault();
                }
            }
        }
    }
});

var escapeHtml = function() {
    var buf = {
        '"': "&quot;",
        "&": "&amp;",
        "<": "&lt;",
        ">": "&gt;"
    };
    return function(messageFormat) {
        return messageFormat.replace(/[\"&<>]/g, function(off) {
            return buf[off];
        });
    };
}();
/*window.onbeforeunload = function() {
    return "You are leaving Agar.io.";
};*/
var disconnectTimeout;
$(window).focus(function() {
    isWindowFocus = true;
    if (disconnectTimeout) {
        clearTimeout(disconnectTimeout);
    }
}).blur(function() {
    isWindowFocus = false;
}), jQuery.cachedScript = function(url, options) {
    return options = $.extend(options || {}, {
        dataType: "script",
        cache: true,
        url: url
    }), jQuery.ajax(options);
}, drawMinimapNodes(), updateGameInfoDiv(), clearOldNodesData(), updateLbDiv(), updateScoreDiv(), $.cachedScript("https://cdnjs.cloudflare.com/ajax/libs/jquery.perfect-scrollbar/0.6.8/js/min/perfect-scrollbar.jquery.min.js").done(function(dataAndEvents, deepDataAndEvents) {
    chatRoom.createScrollBar();
}), $.cachedScript('https://cdnjs.cloudflare.com/ajax/libs/jquery-toast-plugin/1.3.2/jquery.toast.js').done(function(dataAndEvents, deepDataAndEvents) {
    var restoreScript;
    for (; restoreScript = toastQueue.shift();) {
        chatRoom.popup(restoreScript);
    }
}), $("#hotkeys_setting #hotkey_table").appendTo("#hotkeysoverlaycontent");
var handleResource = function(timeoutKey, url) {
    if (timeoutKey && url) {
        if (!customSkin[timeoutKey]) {
            var img = new Image;
            img.onload = function() {
                customSkin[timeoutKey] = this;
                if (myApp.getCustomSkinUrl() == timeoutKey) {
                    myApp.changePreviewImage(this.src);
                }
            };
            img.onerror = function() {
                window.URL.revokeObjectURL(url);
                skinDownloadFail[timeoutKey] = skinDownloadFail[timeoutKey] ? skinDownloadFail[timeoutKey] + 1 : 1;
                console.log("Load image error");
            };
            img.src = url;
        }
    } else {
        console.log(" ** null in download object url, return;");
    }
};
$('#virusColor').minicolors({
    defaultValue: getLocalStorage("virusColor") || "rgba(7, 68, 212, 0.47)",
    change: function(v, start1) {
        setLocalStorage("virusColor", v);
    }
});
$('#virusStrokeColor').minicolors({
    defaultValue: getLocalStorage("virusStrokeColor") || "rgba(8, 73, 212, 1)",
    change: function(v, start1) {
        setLocalStorage("virusStrokeColor", v);
    }
});
$("#backgroundColor").minicolors({
    defaultValue: getLocalStorage("backgroundColor") || "rgba(0, 0, 0, 1)",
    change: function(v, start1) {
        setLocalStorage("backgroundColor", v);
        $("body").css("background-color", v);
    }
}), $("body").css("background-color", getLocalStorage("backgroundColor") || "rgba(0, 0, 0, 1)"), $("#borderColor").minicolors({
    defaultValue: getLocalStorage("borderColor") || "rgba(255, 255, 255, 1)",
    change: function(v, start1) {
        setLocalStorage("borderColor", v);
    }
}), $("#pelletColor").minicolors({
    defaultValue: getLocalStorage("pelletColor") || "rgba(8, 73, 212, 1)",
    change: function(v, start1) {
        setLocalStorage("pelletColor", v);
        $(".sender").css("color", v);
        $(".toast_sender").css("color", v);
        $(".leaderboard .header").css("color", v);
    }
}), $(".sender").css("color", getLocalStorage("pelletColor") || "#0849d4"), $(".toast_sender").css("color", getLocalStorage("pelletColor") || "#0849d4"), $(".leaderboard .header").css("color", getLocalStorage("pelletColor") || "#0849d4");

function setCurrentSkin() {
	var skin_url = $(".skin-url").val();
	if (skin_url && skin_url != "") {
		$(".skin").attr("src", $(".skin-url").val());
	}
}

function setImageDefault() {
	$(".skin-url").val(defaultSkin);
	$(".skin-url").change();
}