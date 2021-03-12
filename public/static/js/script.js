
function w3_open() {
    document.getElementById("mySidebar").style.display = "block";
}

function w3_close() {
    document.getElementById("mySidebar").style.display = "none";
}
function subMenu() {
    document.getElementById("submenu").style.display = "block";
}
function endpoints() {
    document.getElementById("endpoint").style.display = "block";
}
function portScan() {
    document.getElementById("portscan").style.display = "block";
}
function Nuclei() {
    document.getElementById("nuclei").style.display = "block";
}
function cveScan() {
    document.getElementById("cvescan").style.display = "block";
}
function params() {
    document.getElementById("params").style.display = "block";
}
function custom() {
    document.getElementById("custom").style.display = "block";
}
function cors() {
    document.getElementById("cors").style.display = "block";
}
function java() {
    document.getElementById("java").style.display = "block";
}
function secret() {
    document.getElementById("secret").style.display = "block";
}
function brute() {
    document.getElementById("brute").style.display = "block";
}
function crlf() {
    document.getElementById("crlf").style.display = "block";
}
function broken_links() {
    document.getElementById("broken_links").style.display = "block";
}
function github() {
    document.getElementById("github").style.display = "block";
}
function linkss() {
    alert("Make sure Javascript exists in Database");
    document.getElementById("links").style.display = "block";
}

function serverStats() {
    var xhttp = new XMLHttpRequest();
    xhttp.onreadystatechange = function () {
        if (this.readyState == 4 && this.status == 200) {
            alert(this.responseText);
        }
    };
    xhttp.open("GET", "/server-status", true);
    xhttp.send();
}

/*------------ 403 Bypass -----------*/

function bypass403() {
    var url = document.getElementById("url_403").value;
    var xhttp = new XMLHttpRequest();
    document.getElementById("result4033").style.display = 'block';
    xhttp.onreadystatechange = function () {
        if (this.readyState == 4 && this.status == 200) {
            if (this.responseText == "Error") {
                document.getElementById("result4033").style.display = 'none';
                document.getElementById("result403").style.display = 'block';
            }
            else {
                alert(this.responseText);
            }
        }
    };
    xhttp.open("GET", "/bypass-403?url=" + url, true);
    xhttp.send();

}


/*------------ Hidden Parameters with Arjun -----------*/

function hidden_params() {
    var url = document.getElementById("urls").value;
    var xhttp = new XMLHttpRequest();
    document.getElementById("successParams").style.display = 'block';
    //if cookies are included
    if ((document.getElementById("cookies").value).length != 0) {
        var headers = document.getElementById("cookies").value;
        xhttp.onreadystatechange = function () {
            if (this.readyState == 4 && this.status == 200) {
                if (this.responseText == "Error") {
                    document.getElementById("successParams").style.display = 'none';
                    document.getElementById("failedParams").style.display = 'block';
                }
                else {
                    alert(this.responseText);
                }
            }
        };
        xhttp.open("GET", "/arjun?url=" + url + "&headers=" + headers, true);
        xhttp.send();
    }
    else {
        //if cookies are not included
        xhttp.onreadystatechange = function () {
            if (this.readyState == 4 && this.status == 200) {
                if (this.responseText == "Error") {
                    document.getElementById("successParams").style.display = 'none';
                    document.getElementById("failedParams").style.display = 'block';
                }
                else {
                    alert(this.responseText);
                }
            }
        };
        xhttp.open("GET", "/arjun?url=" + url, true);
        xhttp.send();
    }

}

/*------------ JavaScript Monitor -----------*/

function jsMon() {
    var url = document.getElementById("monUrls").value;
    var name = document.getElementById("scanName").value;
    var xhttp = new XMLHttpRequest();
    xhttp.onreadystatechange = function () {
        if (this.readyState == 4 && this.status == 200) {
            if (this.responseText == "Error") {
                document.getElementById("qsSuccess").style.display = 'none';
                document.getElementById("qsFailed").style.display = 'block';
            }
            else {
                document.getElementById("qsSuccess").style.display = 'block';
            }
        }
    };
    xhttp.open("GET", "/jsmon?url=" + url + "&name=" + name, true);
    xhttp.send();

}

function onJs() {

    var xhttp = new XMLHttpRequest();
    xhttp.onreadystatechange = function () {
        if (this.readyState == 4 && this.status == 200) {
            files = this.responseText;
            document.getElementById("totalTarget").innerHTML = files;
        }
    };
    xhttp.open("GET", "/jsmon", true);
    xhttp.send();


}

//Subdomain Monitor with CertEagle

function subMon() {
    var xhttp = new XMLHttpRequest();
    xhttp.onreadystatechange = function () {
        if (this.readyState == 4 && this.status == 200) {
            files = this.responseText;
            document.getElementById("subdomainsMon").innerHTML = files;
        }
    };
    xhttp.open("GET", "/certeagle", true);
    xhttp.send();

}

/*============================== Ongoing Scan Check ============================ */
function onScan() {
    var xhttp = new XMLHttpRequest();
    xhttp.onreadystatechange = function () {
        if (this.readyState == 4 && this.status == 200) {
            result = this.responseText;
            var temp = result.replace(/\[/g, "");
            var temp1 = temp.replace(/\]/g, "");
            document.getElementById("scanList").innerHTML = Array.from(temp1.split(",")).length;
            document.getElementById("scanData").innerHTML = temp1;
            // alert(Array.from(result.split(",")));
        }
    };
    xhttp.open("GET", "/ongoing-scan", true);
    xhttp.send();
}



/*============================== Google Hacking ============================ */

function googleHacking(option) {
    var target = document.getElementById('dorkTarget').value;
    var link = "https://www.google.com/search?q=site:" + target;
    if (option == 1) {
        var dork = "+ext:doc+|+ext:docx+|+ext:odt+|+ext:rtf+|+ext:sxw+|+ext:psw+|+ext:ppt+|+ext:pptx+|+ext:pps+|+ext:csv+|+ext:txt+|+ext:pdf";
        var url = link + dork;
        window.open(url, "_blank");
    }
    if (option == 2) {
        var dork = "+intitle:index.of";
        var url = link + dork;
        window.open(url, "_blank");
    }
    if (option == 3) {
        var dork = "+ext:xml+|+ext:conf+|+ext:cnf+|+ext:reg+|+ext:inf+|+ext:rdp+|+ext:cfg+|+ext:txt+|+ext:ora+|+ext:ini+|+ext:env";
        var url = link + dork;
        window.open(url, "_blank");
    }
    if (option == 4) {
        var dork = "+ext:sql+|+ext:dbf+|+ext:mdb";
        var url = link + dork;
        window.open(url, "_blank");
    }
    if (option == 5) {
        var dork = "+ext:log";
        var url = link + dork;
        window.open(url, "_blank");
    }
    if (option == 6) {
        var dork = "+ext:bkf+|+ext:bkp+|+ext:bak+|+ext:old+|+ext:backup";
        var url = link + dork;
        window.open(url, "_blank");
    }
    if (option == 7) {
        var dork = '+inurl:login+|+inurl:signin+|+intitle:Login+|+intitle:"sign+in"+|+inurl:auth';
        var url = link + dork;
        window.open(url, "_blank");
    }
    if (option == 8) {
        var dork = '+intext:"sql+syntax+near"+|+intext:"syntax+error+has+occurred"+|+intext:"incorrect+syntax+near"+|+intext:"unexpected+end+of+SQL+command"+|+intext:"Warning:+mysql_connect()"+|+intext:"Warning:+mysql_query()"+|+intext:"Warning:+pg_connect()"';
        var url = link + dork;
        window.open(url, "_blank");
    }
    if (option == 9) {
        var dork = '+"PHP+Parse+error"+|+"PHP+Warning"+|+"PHP+Error"';
        var url = link + dork;
        window.open(url, "_blank");
    }
    if (option == 10) {
        var uni = "https://www.google.com/search?q=site:";
        var dork = 'pastebin.com%20|%20site:paste2.org%20|%20site:pastehtml.com%20|%20site:slexy.org%20|%20site:snipplr.com%20|%20site:snipt.net%20|%20site:textsnip.com%20|%20site:bitpaste.app%20|%20site:justpaste.it%20|%20site:heypasteit.com%20|%20site:hastebin.com%20|%20site:dpaste.org%20|%20site:dpaste.com%20|%20site:codepad.org%20|%20site:jsitor.com%20|%20site:codepen.io%20|%20site:jsfiddle.net%20|%20site:dotnetfiddle.net%20|%20site:phpfiddle.org%20|%20site:ide.geeksforgeeks.org%20|%20site:repl.it%20|%20site:ideone.com%20|%20site:paste.debian.net%20|%20site:paste.org%20|%20site:paste.org.ru%20|%20site:codebeautify.org%20%20|%20site:codeshare.io%20|%20site:trello.com%20%22' + target + '"';
        var url = uni + dork;
        window.open(url, "_blank");
    }
    if (option == 11) {
        var uni = "https://www.google.com/search?q=site:";
        var dork = 'github.com%20|%20site:gitlab.com%20%22' + target + '"';
        var url = uni + dork;
        window.open(url, "_blank");
    }
    if (option == 12) {
        var dork = '+inurl:signup+|+inurl:register+|+intitle:Signup';
        var url = link + dork;
        window.open(url, "_blank");
    }
    if (option == 13) {
        var dork = '+inurl:access_token';
        var url = link + dork;
        window.open(url, "_blank");
    }
}

