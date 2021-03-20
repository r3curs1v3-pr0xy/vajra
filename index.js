const bodyParser = require('body-parser');
const express = require('express');
const path = require('path');
const app = express();
const http = require('http');
const cradle = require('cradle');
const exec = require('child_process').exec;
const { spawn } = require('child_process');
const { waitForDebugger, url } = require('inspector');
const { readFileSync } = require('fs');
const fs = require('fs');
const { json } = require('body-parser');
const { stdout } = require('process');
const { WSANOTINITIALISED } = require('constants');
const jwt = require('jsonwebtoken');
var cookieParser = require('cookie-parser');
const rateLimit = require('express-rate-limit');
const { get } = require('jquery');

//This keeps vajra running in every situation
process.on("uncaughtException", function (err) {
    console.error(err);
    console.log("Node NOT Exiting...");
});


//Static Files
app.use('/static', express.static(__dirname + '/public/static'));
app.use('/css', express.static(__dirname + '/public/static/css'));
app.use('/js', express.static(__dirname + '/public/static/'));
app.use('/img', express.static(__dirname + '/public/static/img'));


//Set Views
app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'ejs');
app.use(cookieParser());

//Body Parser
var jsonParser = bodyParser.json();
var urlencodedParser = bodyParser.urlencoded({
    extended: false
});

//Takes get request i.e when page load
app.get('', (req, res) => {
    res.render('home', {
        text: ""
    });
});



//Get Scan Type and Target name from user

var ongoing_scan = []; //store list of ongoing scan

app.post('/form-data/', urlencodedParser, (req, res) => {

    jwt.verify(req.cookies.auth, 'fIskNyRbdGmdaekbMSRlAkU5RIJc6V7I', (err) => {
        if (err) {
            res.status(403).send("You're not authorized to use this framework!");
        }
        else {


            //Connect to database

            var connection = new (cradle.Connection)('http://127.0.0.1', 5984, {
                auth: {
                    username: 'admin',
                    password: 'hackwithme'
                },
                cache: true,
                retries: 3,
                retryTimeout: 3 * 1000
            });


            // Create Database of unique target
            if ((req.body.domain).match(/\./g).length > 1) { //checks whether target is root domain or subdomain
                targets = req.body.domain.replace(".", ""); //replace first dot with "" as cradle doesn't support double underscore
                target = targets.replace(".", "_"); // Dot is not allowed in CouchDB database name
            }
            else {
                target = req.body.domain.replace(".", "_"); // Dot is not allowed in CouchDB 
            }

            var db = connection.database(target);

            async function create() {
                await db.create((err) => {
                    if (err) {
                        res.render('index', {
                            text: '' //if error occurs in creating DB then it already exists in DB
                        });
                        mainFunction();
                    }
                    else {
                        res.render('index', {
                            text: ''
                        });

                        //Update revision limit of database
                        exec('curl -X PUT -d "10000000" http://admin:hackwithme@127.0.0.1:5984/' + target + '/_revs_limit', (err) => {
                            if (err) {
                                console.log(err);
                            };
                        });
                        mainFunction();

                    }
                });
            }; create();



            //============================== Main Function ======================================


            function mainFunction() {


                //============================== Extract Subdomains ======================================



                //Only if Subfinder is selected
                if (req.body.subfinder && !req.body.amass && !req.body.assetfinder) {
                    var msg = "Subdomain Scan for " + req.body.domain;
                    ongoing_scan.push(msg); // add to ongoing scan array
                    exec('./tools/subdomains.sh ' + "subfinder " + req.body.domain, { maxBuffer: 1024 * 9200 }, (err) => {
                        if (err) {
                            console.log(err);
                            db.save("all_subdomains", {
                                "all_subdomains": "Max Buffer Exceed" //Save error message if target subdomains exceed maxBuffer
                            }, (err) => {
                                if (err) {
                                    console.log(err);
                                }
                            });
                            //Removes ongoing Scan from array
                            const index = ongoing_scan.indexOf(msg);
                            if (index > -1) {
                                ongoing_scan.splice(index, 1);
                            }
                        }
                        else {
                            try {
                                var data = fs.readFileSync('./tools/' + req.body.domain + '_resolve.txt.json', { encoding: 'utf-8' });
                            }
                            catch {
                                //Removes ongoing Scan from array
                                const index = ongoing_scan.indexOf(msg);
                                if (index > -1) {
                                    ongoing_scan.splice(index, 1);

                                }
                            }
                            var obj = JSON.parse(data);
                            db.save('all_subdomains', {
                                "all_subdomains": obj
                            }, (err, res) => {
                                if (err) {
                                    console.log(err);
                                }
                                else {
                                    var data1 = fs.readFileSync('./tools/' + req.body.domain + '_valid_resolve.txt', { encoding: 'utf-8' }).split('\n');
                                    db.save('valid_subdomains', {
                                        "valid_subdomains": data1
                                    }, (err) => {
                                        if (err) {
                                            console.log(err);
                                        }
                                        else {
                                            exec('rm -f ./tools/' + req.body.domain + '_valid_resolve.txt', (err) => {
                                                if (err) {
                                                    console.log(err);
                                                }

                                                //Removes ongoing Scan from array
                                                const index = ongoing_scan.indexOf(msg);
                                                if (index > -1) {
                                                    ongoing_scan.splice(index, 1);
                                                }
                                            });
                                        }
                                    });
                                }
                            });
                            exec('rm -f ./tools/' + req.body.domain + '_resolve.txt.json', (err) => {
                                if (err) {
                                    console.log(err);
                                }
                            });

                        }
                    });
                }


                //only if assetfinder is selected

                if (req.body.assetfinder && !req.body.amass && !req.body.subfinder) {
                    exec('./tools/subdomains.sh ' + "assetfinder " + req.body.domain, { maxBuffer: 1024 * 9200 }, (err) => {
                        if (err) {
                            console.log(err);
                            db.save('all_subdomains', {
                                "all_subdomains": "Max Buffer Exceed"
                            }, (err) => {
                                if (err) {
                                    console.log(err);
                                    //Removes ongoing Scan from array
                                    const index = ongoing_scan.indexOf(msg);
                                    if (index > -1) {
                                        ongoing_scan.splice(index, 1);

                                    }
                                }
                                //Removes ongoing Scan from array
                                const index = ongoing_scan.indexOf(msg);
                                if (index > -1) {
                                    ongoing_scan.splice(index, 1);

                                }
                            });
                        }
                        else {
                            try {
                                var data = fs.readFileSync('./tools/' + req.body.domain + '_resolve.txt.json', { encoding: 'utf-8' });
                            }
                            catch {
                                //Removes ongoing Scan from array
                                const index = ongoing_scan.indexOf(msg);
                                if (index > -1) {
                                    ongoing_scan.splice(index, 1);

                                }
                            }
                            var obj = JSON.parse(data);
                            db.save('all_subdomains', {
                                "all_subdomains": obj
                            }, (err, res) => {
                                if (err) {
                                    console.log(err);
                                }
                                else {
                                    var data1 = fs.readFileSync('./tools/' + req.body.domain + '_valid_resolve.txt', { encoding: 'utf-8' }).split('\n');
                                    db.save('valid_subdomains', {
                                        "valid_subdomains": data1
                                    }, (err) => {
                                        if (err) {
                                            console.log(err);
                                        }
                                        else {
                                            exec('rm -f ./tools/' + req.body.domain + '_valid_resolve.txt', (err) => {
                                                if (err) {
                                                    console.log(err);
                                                }
                                            });
                                        }
                                    });
                                }
                            });
                            exec('rm -f ./tools/' + req.body.domain + '_resolve.txt.json', (err) => {
                                if (err) {
                                    console.log(err);
                                }
                            });

                        }
                    });
                }


                //only if amass is selected

                if (req.body.amass && !req.body.subfinder && !req.body.assetfinder) {
                    var msg = "Subdomain Scans for " + req.body.domain;
                    ongoing_scan.push(msg); // add to ongoing scan array
                    exec('./tools/subdomains.sh ' + "amass " + req.body.domain, { maxBuffer: 1024 * 9200 }, (err) => {
                        if (err) {
                            console.log(err);
                            db.save('all_subdomains', {
                                "all_subdomains": "Max Buffer Exceed"
                            }, (err) => {
                                if (err) {
                                    console.log(err);
                                }
                            });
                            //Removes ongoing Scan from array
                            const index = ongoing_scan.indexOf(msg);
                            if (index > -1) {
                                ongoing_scan.splice(index, 1);
                            }
                        }
                        else {
                            try {
                                var data = fs.readFileSync('./tools/' + req.body.domain + '_resolve.txt.json', { encoding: 'utf-8' });
                            }
                            catch {
                                //Removes ongoing Scan from array
                                const index = ongoing_scan.indexOf(msg);
                                if (index > -1) {
                                    ongoing_scan.splice(index, 1);

                                }
                            }
                            var obj = JSON.parse(data);
                            db.save('all_subdomains', {
                                "all_subdomains": obj
                            }, (err, res) => {
                                if (err) {
                                    console.log(err);
                                }
                                else {
                                    var data1 = fs.readFileSync('./tools/' + req.body.domain + '_valid_resolve.txt', { encoding: 'utf-8' }).split('\n');
                                    db.save('valid_subdomains', {
                                        "valid_subdomains": data1
                                    }, (err) => {
                                        if (err) {
                                            console.log(err);
                                        }
                                        else {
                                            exec('rm -f ./tools/' + req.body.domain + '_valid_resolve.txt', (err) => {
                                                if (err) {
                                                    console.log(err);
                                                }
                                                //Removes ongoing Scan from array
                                                const index = ongoing_scan.indexOf(msg);
                                                if (index > -1) {
                                                    ongoing_scan.splice(index, 1);
                                                }
                                            });
                                        }
                                    });
                                }
                            });
                            exec('rm -f ./tools/' + req.body.domain + '_resolve.txt.json', (err) => {
                                if (err) {
                                    console.log(err);
                                }
                            });
                        }
                    });
                }


                //if all methods  is selected

                if (req.body.assetfinder && req.body.amass && req.body.subfinder) {
                    var msg = "Subdomain Scans for " + req.body.domain;
                    ongoing_scan.push(msg); // add to ongoing scan array
                    exec('./tools/subdomains.sh ' + "all " + req.body.domain, { maxBuffer: 1024 * 9200 }, (err) => {
                        if (err) {
                            console.log(err);
                            db.save('all_subdomains', {
                                "all_subdomains": "Max Buffer Exceed"
                            }, (err) => {
                                if (err) {
                                    console.log(err);
                                }
                            });
                            //Removes ongoing Scan from array
                            const index = ongoing_scan.indexOf(msg);
                            if (index > -1) {
                                ongoing_scan.splice(index, 1);
                            }
                        }
                        else {
                            var data = fs.readFileSync('./tools/' + req.body.domain + '_final_subdomains_resolve.txt.json', { encoding: 'utf-8' });
                            var obj = JSON.parse(data);
                            db.save('all_subdomains', {
                                "all_subdomains": obj
                            }, (err, res) => {
                                if (err) {
                                    console.log(err);
                                    //Removes ongoing Scan from array
                                    const index = ongoing_scan.indexOf(msg);
                                    if (index > -1) {
                                        ongoing_scan.splice(index, 1);
                                    }
                                }
                                else {
                                    var data1 = fs.readFileSync('./tools/' + req.body.domain + '_final_valid_subdomains_resolve.txt', { encoding: 'utf-8' }).split('\n');
                                    db.save('valid_subdomains', {
                                        "valid_subdomains": data1
                                    }, (err) => {
                                        if (err) {
                                            console.log(err);
                                            //Removes ongoing Scan from array
                                            const index = ongoing_scan.indexOf(msg);
                                            if (index > -1) {
                                                ongoing_scan.splice(index, 1);
                                            }
                                        }
                                        else {
                                            exec('rm -f ./tools/' + req.body.domain + '_final_valid_subdomains_resolve.txt', (err) => {
                                                if (err) {
                                                    console.log(err);
                                                }
                                                //Removes ongoing Scan from array
                                                const index = ongoing_scan.indexOf(msg);
                                                if (index > -1) {
                                                    ongoing_scan.splice(index, 1);
                                                }
                                            });
                                        }
                                    });
                                }
                            });
                            exec('rm -f ./tools/' + req.body.domain + '_final_subdomains_resolve.txt.json', (err) => {
                                if (err) {
                                    console.log(err);
                                }
                            });
                        }
                    });
                }






                //================================ Port Scanner ==========================

                //scan for < 10,000 ports

                if (req.body.small) {
                    ongoing_scan.push("Port Scan for " + req.body.domain); // add to ongoing scan array
                    //if subdomains is selected
                    if (req.body.subPort) {
                        exec('./tools/sub-port-scan.sh ' + req.body.domain + ' small', (err) => {
                            if (err) {
                                console.log(err);
                                //Removes ongoing Scan from array
                                const index = ongoing_scan.indexOf("Port Scan for " + req.body.domain);
                                if (index > -1) {
                                    ongoing_scan.splice(index, 1);
                                }
                            }
                            else {
                                var data = fs.readFileSync('./tools/' + req.body.domain + '_result.txt', { encoding: 'utf-8' });
                                db.save('small_port_scan_with_subdomains', {
                                    "small_port_scan_with_subdomains": data.split("\n")
                                }, (err) => {
                                    if (err) {
                                        console.log(err);
                                        //Removes ongoing Scan from array
                                        const index = ongoing_scan.indexOf("Port Scan for " + req.body.domain);
                                        if (index > -1) {
                                            ongoing_scan.splice(index, 1);
                                        }
                                    }
                                    //Removes ongoing Scan from array
                                    const index = ongoing_scan.indexOf("Port Scan for " + req.body.domain);
                                    if (index > -1) {
                                        ongoing_scan.splice(index, 1);
                                    }
                                });
                                exec('rm -f ./tools/' + req.body.domain + '_result.txt', (err) => {
                                    if (err) {
                                        console.log(err);
                                    }
                                });
                            }

                        });

                    }
                    else {
                        //if subdomains is not selected
                        exec('./tools/port-scan.sh ' + req.body.domain + ' small', (err) => {
                            if (err) {
                                console.log(err);
                                //Removes ongoing Scan from array
                                const index = ongoing_scan.indexOf("Port Scan for " + req.body.domain);
                                if (index > -1) {
                                    ongoing_scan.splice(index, 1);
                                }
                            }
                            else {
                                var data = fs.readFileSync('./tools/' + req.body.domain + '_open-ports.txt', { encoding: 'utf-8' });
                                db.save('small_port_scan', {
                                    "small_port_scan": data.split("\n")
                                }, (err) => {
                                    if (err) {
                                        console.log(err);
                                        //Removes ongoing Scan from array
                                        const index = ongoing_scan.indexOf("Port Scan for " + req.body.domain);
                                        if (index > -1) {
                                            ongoing_scan.splice(index, 1);
                                        }
                                    }
                                    //Removes ongoing Scan from array
                                    const index = ongoing_scan.indexOf("Port Scan for " + req.body.domain);
                                    if (index > -1) {
                                        ongoing_scan.splice(index, 1);
                                    }
                                });
                                exec('rm -f ./tools/' + req.body.domain + '_open-ports.txt', (err) => {
                                    if (err) {
                                        console.log(err);
                                    }
                                });
                            }
                        });

                    }
                }



                //scan for < 30,000 ports

                if (req.body.medium) {
                    ongoing_scan.push("Port Scan for " + req.body.domain); // add to ongoing scan array
                    //if subdomains is selected
                    if (req.body.subPort) {
                        exec('./tools/sub-port-scan.sh ' + req.body.domain + ' medium', (err) => {
                            if (err) {
                                console.log(err);
                                //Removes ongoing Scan from array
                                const index = ongoing_scan.indexOf("Port Scan for " + req.body.domain);
                                if (index > -1) {
                                    ongoing_scan.splice(index, 1);
                                }
                            }
                            else {
                                var data = fs.readFileSync('./tools/' + req.body.domain + '_result.txt', { encoding: 'utf-8' });
                                db.save('mid_port_scan_with_subdomains', {
                                    "mid_port_scan_with_subdomains": data.split("\n")
                                }, (err) => {
                                    if (err) {
                                        console.log(err);
                                        //Removes ongoing Scan from array
                                        const index = ongoing_scan.indexOf("Port Scan for " + req.body.domain);
                                        if (index > -1) {
                                            ongoing_scan.splice(index, 1);
                                        }
                                    }
                                    //Removes ongoing Scan from array
                                    const index = ongoing_scan.indexOf("Port Scan for " + req.body.domain);
                                    if (index > -1) {
                                        ongoing_scan.splice(index, 1);
                                    }
                                });
                                exec('rm -f ./tools/' + req.body.domain + '_result.txt', (err) => {
                                    if (err) {
                                        console.log(err);
                                    }
                                });
                            }

                        });

                    }
                    else {
                        //if subdomains is not selected
                        exec('./tools/port-scan.sh ' + req.body.domain + ' medium', (err) => {
                            if (err) {
                                console.log(err);
                                //Removes ongoing Scan from array
                                const index = ongoing_scan.indexOf("Port Scan for " + req.body.domain);
                                if (index > -1) {
                                    ongoing_scan.splice(index, 1);
                                }
                            }
                            else {
                                var data = fs.readFileSync('./tools/' + req.body.domain + '_open-ports.txt', { encoding: 'utf-8' });
                                db.save('mid_port_scan', {
                                    "mid_port_scan": data.split("\n")
                                }, (err) => {
                                    if (err) {
                                        console.log(err);
                                        //Removes ongoing Scan from array
                                        const index = ongoing_scan.indexOf("Port Scan for " + req.body.domain);
                                        if (index > -1) {
                                            ongoing_scan.splice(index, 1);
                                        }
                                    }
                                    //Removes ongoing Scan from array
                                    const index = ongoing_scan.indexOf("Port Scan for " + req.body.domain);
                                    if (index > -1) {
                                        ongoing_scan.splice(index, 1);
                                    }
                                });
                                exec('rm -f ./tools/' + req.body.domain + '_open-ports.txt', (err) => {
                                    if (err) {
                                        console.log(err);
                                    }
                                });
                            }
                        });
                    }
                }



                //Full ports Scan

                if (req.body.full) {
                    ongoing_scan.push("Port Scan for " + req.body.domain); // add to ongoing scan array
                    //if subdomains is selected
                    if (req.body.subPort) {
                        exec('./tools/sub-port-scan.sh ' + req.body.domain + ' full', (err) => {
                            if (err) {
                                console.log(err);
                                //Removes ongoing Scan from array
                                const index = ongoing_scan.indexOf("Port Scan for " + req.body.domain);
                                if (index > -1) {
                                    ongoing_scan.splice(index, 1);
                                }
                            }
                            else {
                                var data = fs.readFileSync('./tools/' + req.body.domain + '_result.txt', { encoding: 'utf-8' });
                                db.save('full_port_scan_with_subdomains', {
                                    "full_port_scan_with_subdomains": data.split("\n")
                                }, (err, res) => {
                                    if (err) {
                                        console.log(err);
                                        //Removes ongoing Scan from array
                                        const index = ongoing_scan.indexOf("Port Scan for " + req.body.domain);
                                        if (index > -1) {
                                            ongoing_scan.splice(index, 1);
                                        }

                                    }
                                    //Removes ongoing Scan from array
                                    const index = ongoing_scan.indexOf("Port Scan for " + req.body.domain);
                                    if (index > -1) {
                                        ongoing_scan.splice(index, 1);
                                    }
                                });
                                exec('rm -f ./tools/' + req.body.domain + '_result.txt', (err) => {
                                    if (err) {
                                        console.log(err);
                                    }
                                });
                            }

                        });

                    }
                    else {
                        //if subdomains is not selected
                        exec('./tools/port-scan.sh ' + req.body.domain + ' full', (err) => {
                            if (err) {
                                console.log(err);
                                //Removes ongoing Scan from array
                                const index = ongoing_scan.indexOf("Port Scan for " + req.body.domain);
                                if (index > -1) {
                                    ongoing_scan.splice(index, 1);
                                }
                            }
                            else {
                                var data = fs.readFileSync('./tools/' + req.body.domain + '_open-ports.txt', { encoding: 'utf-8' });
                                db.save('full_port_scan', {
                                    "full_port_scan": data.split("\n")
                                }, (err, res) => {
                                    if (err) {
                                        console.log(err);
                                        //Removes ongoing Scan from array
                                        const index = ongoing_scan.indexOf("Port Scan for " + req.body.domain);
                                        if (index > -1) {
                                            ongoing_scan.splice(index, 1);
                                        }
                                    }
                                    //Removes ongoing Scan from array
                                    const index = ongoing_scan.indexOf("Port Scan for " + req.body.domain);
                                    if (index > -1) {
                                        ongoing_scan.splice(index, 1);
                                    }
                                });
                                exec('rm -f ./tools/' + req.body.domain + '_open-ports.txt', (err) => {
                                    if (err) {
                                        console.log(err);
                                    }
                                });
                            }
                        });
                    }
                }

                //================================ Broken Links Checker =============================

                //Broken Link Checker
                if (req.body.broken_links) {
                    ongoing_scan.push("Broken Links Checker for " + req.body.domain); // add to ongoing scan array
                    exec('./tools/script.sh ' + req.body.domain + ' broken_links', { maxBuffer: 1024 * 5200 }, (err) => {
                        if (err) {
                            console.log(err);
                            db.save('broken_links', {
                                "broken_links": "Max Buffer Exceed"
                            }, (err) => {
                                if (err) {
                                    console.log(err);
                                }
                                //Removes from ongoing Scan
                                const index = ongoing_scan.indexOf("Broken Links Checker for " + req.body.domain);
                                if (index > -1) {
                                    ongoing_scan.splice(index, 1);
                                }
                            });
                        }
                        else {
                            var data = fs.readFileSync('./tools/' + req.body.domain + '_broken_links.txt', { encoding: 'utf-8' }).split("\n");
                            db.save('broken_links', {
                                "broken_links": data
                            }, (err) => {
                                if (err) {
                                    console.log(err);
                                }
                                //Removes from ongoing Scan
                                const index = ongoing_scan.indexOf("Broken Links Checker for " + req.body.domain);
                                if (index > -1) {
                                    ongoing_scan.splice(index, 1);
                                }
                            });
                            exec('rm -f ./tools/' + req.body.domain + '_broken_links.txt', (err) => {
                                if (err) {
                                    console.log(err);
                                }
                            });
                        }
                    });
                }

                //if subdomains is selected

                if (req.body.subdomainsBroken) {
                    ongoing_scan.push("Broken Links Checker for " + req.body.domain); // add to ongoing scan array
                    async function crlf() {
                        await db.get("valid_subdomains", (err, res) => {
                            if (err) {
                                console.log(err);
                                //Removes from ongoing Scan
                                const index = ongoing_scan.indexOf("Broken Links Checker for " + req.body.domain);
                                if (index > -1) {
                                    ongoing_scan.splice(index, 1);
                                }
                            }
                            else {
                                res.valid_subdomains.forEach((element) => {
                                    fs.appendFileSync('./tools/' + req.body.domain + '_brokens.txt', element + ("\n"), { encoding: 'utf-8' });
                                });
                                exec('./tools/script.sh ' + req.body.domain + ' broken_subs', { maxBuffer: 1024 * 20000 }, (err) => {
                                    if (err) {
                                        console.log(err);
                                        //Removes from ongoing Scan
                                        const index = ongoing_scan.indexOf("Broken Links Checker for " + req.body.domain);
                                        if (index > -1) {
                                            ongoing_scan.splice(index, 1);
                                        }
                                    }
                                    else {
                                        var data = fs.readFileSync('./tools/' + req.body.domain + '_broken_links.txt', { encoding: 'utf-8' }).split("\n");
                                        db.save('broken_links_on_subdomains', { broken_links_subdomains: data }, (err) => {
                                            if (err) {
                                                console.log(err);
                                                //Removes from ongoing Scan
                                                const index = ongoing_scan.indexOf("Broken Links Checker for " + req.body.domain);
                                                if (index > -1) {
                                                    ongoing_scan.splice(index, 1);
                                                }
                                            }
                                            else {
                                                exec('rm -f ./tools/' + req.body.domain + '_broken_links.txt', (err) => {
                                                    if (err) {
                                                        console.log(err);
                                                    }
                                                    //Removes from ongoing Scan
                                                    const index = ongoing_scan.indexOf("Broken Links Checker for " + req.body.domain);
                                                    if (index > -1) {
                                                        ongoing_scan.splice(index, 1);
                                                    }
                                                });
                                            }
                                        });
                                    }
                                });
                            }
                        });

                    } crlf();
                }


                //================================ CVE Scan =============================

                if (req.body.rootCVE) {
                    ongoing_scan.push("CVE Scan for " + req.body.domain); // add to ongoing scan array
                    exec('echo https://www.' + req.body.domain + '| nuclei -t ./tools/nuclei-templates/cves/ -o ./tools/' + req.body.domain + "_cve.txt", { maxBuffer: 1024 * 1200 }, (err) => {
                        if (err) {
                            console.log(err);
                            //Removes from ongoing Scan
                            const index = ongoing_scan.indexOf("CVE Scan for " + req.body.domain);
                            if (index > -1) {
                                ongoing_scan.splice(index, 1);
                            }
                        }
                        else {
                            var x = "Target is Not Vulnerable";
                            if (!fs.existsSync('./tools/' + req.body.domain + '_cve.txt')) {
                                db.save('CVE', {
                                    "CVE": x.split("\n")
                                }, (err) => {
                                    if (err) {
                                        console.log(err);
                                    }
                                    //Removes from ongoing Scan
                                    const index = ongoing_scan.indexOf("CVE Scan for " + req.body.domain);
                                    if (index > -1) {
                                        ongoing_scan.splice(index, 1);
                                    }
                                });
                            }
                            else {
                                var data = fs.readFileSync('./tools/' + req.body.domain + '_cve.txt', { encoding: 'utf-8' }).split("\n");
                                db.save('CVE', {
                                    "CVE": data
                                }, (err, res) => {
                                    if (err) {
                                        console.log(err);
                                        //Removes from ongoing Scan
                                        const index = ongoing_scan.indexOf("CVE Scan for " + req.body.domain);
                                        if (index > -1) {
                                            ongoing_scan.splice(index, 1);
                                        }
                                    }
                                });
                                exec('rm -f ./tools/' + req.body.domain + '_cve.txt', (err) => {
                                    if (err) {
                                        console.log(err);
                                    }
                                });

                            }

                        }
                    }
                    );

                }


                // if subdomains is selected for CVE Scan 
                if (req.body.subdomainCVE) {
                    ongoing_scan.push("CVE Scan for " + req.body.domain); // add to ongoing scan array
                    exec('subfinder -d ' + req.body.domain + ' | httpx | tee -a ./tools/' + req.body.domain + '_subdomain.txt', { maxBuffer: 1024 * 20000 }, (err) => {
                        if (err) {
                            console.log(err);
                        }
                        else {
                            exec('./tools/script.sh ' + req.body.domain + ' subNuclei', { maxBuffer: 1024 * 20000 }, (err) => {
                                if (err) {
                                    console.log(err);
                                    //Removes from ongoing Scan
                                    const index = ongoing_scan.indexOf("CVE Scan for " + req.body.domain);
                                    if (index > -1) {
                                        ongoing_scan.splice(index, 1);
                                    }
                                }
                                else {
                                    var data = fs.readFileSync('./tools/' + req.body.domain + '_subdomain_cve.txt', { encoding: 'utf-8' }).split("\n");
                                    db.save('CVE_on_Subdomains', {
                                        "CVE_on_Subdomains": data
                                    }, (err, res) => {
                                        if (err) {
                                            console.log(err);
                                        }
                                        //Removes from ongoing Scan
                                        const index = ongoing_scan.indexOf("CVE Scan for " + req.body.domain);
                                        if (index > -1) {
                                            ongoing_scan.splice(index, 1);
                                        }
                                    });
                                    exec('rm -f ./tools/' + req.body.domain + '_subdomain_cve.txt', (err) => {
                                        if (err) {
                                            console.log(err);
                                        }
                                    });
                                    exec('rm -f ./tools/' + req.body.domain + '_subdomain.txt', (err) => {
                                        if (err) {
                                            console.log(err);
                                        }
                                    });

                                }
                            });
                        }
                    });
                }


                //================================ Extract Endpoints =============================



                // if subdomains is selected
                async function endpoint() {
                    if (req.body.include_subdomains) {
                        ongoing_scan.push("Extracting Endpoints for " + req.body.domain); // add to ongoing scan array
                        await exec('./tools/script.sh ' + req.body.domain + ' include_subdomain', { maxBuffer: 1024 * 20000 }, (err) => { //51200
                            if (err) {
                                console.log(err);
                                //Removes from ongoing Scan
                                const index = ongoing_scan.indexOf("Extracting Endpoints for " + req.body.domain);
                                if (index > -1) {
                                    ongoing_scan.splice(index, 1);
                                }
                            }
                            else {
                                try {
                                    var data = fs.readFileSync('./tools/' + req.body.domain + '_extensionss.txt', { encoding: 'utf-8' }).split("\n");
                                    db.save('Endpoints_with_Subdomains_Extensions', {
                                        "Endpoints_with_Subdomains_Extensions": data
                                    }, (err) => {
                                        if (err) {
                                            console.log(err);
                                        }
                                        else {
                                            exec('rm ./tools/' + req.body.domain + '_extensionss.txt', (err) => {
                                                if (err) {
                                                    console.log(err);
                                                }
                                            });
                                        }
                                    });

                                    var data = fs.readFileSync('./tools/' + req.body.domain + '_endpointss.txt', { encoding: 'utf-8' }).split("\n");

                                    db.save('All_Endpoints_with_Subdomains', {
                                        "All_Endpoints_with_Subdomains": data
                                    }, (err) => {
                                        if (err) {
                                            console.log(err);
                                            //Removes from ongoing Scan
                                            const index = ongoing_scan.indexOf("Extracting Endpoints for " + req.body.domain);
                                            if (index > -1) {
                                                ongoing_scan.splice(index, 1);
                                            }
                                        }
                                        else {
                                            exec('rm ./tools/' + req.body.domain + '_endpointss.txt', (err) => {
                                                if (err) {
                                                    console.log(err);
                                                }
                                            });
                                            //Removes from ongoing Scan
                                            const index = ongoing_scan.indexOf("Extracting Endpoints for " + req.body.domain);
                                            if (index > -1) {
                                                ongoing_scan.splice(index, 1);
                                            }
                                        }
                                    });
                                }
                                catch { // if target data is not available in wayback then removes from ongoing scan
                                    //Removes from ongoing Scan
                                    const index = ongoing_scan.indexOf("Extracting Endpoints for " + req.body.domain);
                                    if (index > -1) {
                                        ongoing_scan.splice(index, 1);
                                    }
                                }




                            }
                        });
                    }


                    //If Subdomain is not selected

                    if (req.body.from_wayback) {
                        ongoing_scan.push("Extracting Endpoints for " + req.body.domain); // add to ongoing scan array

                        await exec('./tools/script.sh ' + req.body.domain + ' from_wayback', { maxBuffer: 1024 * 20200 }, (err) => {
                            if (err) {
                                console.log(err);
                                //Removes from ongoing Scan
                                const index = ongoing_scan.indexOf("Extracting Endpoints for " + req.body.domain);
                                if (index > -1) {
                                    ongoing_scan.splice(index, 1);
                                }

                            }
                            else {
                                try {
                                    var data = fs.readFileSync('./tools/' + req.body.domain + '_extensions.txt', { encoding: 'utf-8' }).split("\n");
                                    db.save('Endpoints_with_Extensions', {
                                        "Endpoints_with_Extensions": data
                                    }, (err) => {
                                        if (err) {
                                            console.log(err);
                                        }
                                        else {
                                            exec('rm ./tools/' + req.body.domain + '_extensions.txt', (err) => {
                                                if (err) {
                                                    console.log(err);
                                                }
                                            });
                                        }
                                    });
                                    var data = fs.readFileSync('./tools/' + req.body.domain + '_endpoints.txt', { encoding: 'utf-8' }).split("\n");
                                    db.save('All_Endpoints', {
                                        "All_Endpoints": data
                                    }, (err) => {
                                        if (err) {
                                            console.log(err);
                                            //Removes from ongoing Scan
                                            const index = ongoing_scan.indexOf("Extracting Endpoints for " + req.body.domain);
                                            if (index > -1) {
                                                ongoing_scan.splice(index, 1);
                                            }
                                        }
                                        else {
                                            exec('rm ./tools/' + req.body.domain + '_endpoints.txt', (err) => {
                                                if (err) {
                                                    console.log(err);
                                                }
                                            });
                                            //Removes from ongoing Scan
                                            const index = ongoing_scan.indexOf("Extracting Endpoints for " + req.body.domain);
                                            if (index > -1) {
                                                ongoing_scan.splice(index, 1);
                                            }
                                        }
                                    });
                                }
                                catch {
                                    // if target data is not available in wayback then removes from ongoing scan
                                    //Removes from ongoing Scan
                                    const index = ongoing_scan.indexOf("Extracting Endpoints for " + req.body.domain);
                                    if (index > -1) {
                                        ongoing_scan.splice(index, 1);
                                    }
                                }

                            }
                        });

                    }


                } endpoint();





                //================================== Extract Javascript =============================

                //Get Javascript from WayBack
                if (req.body.rootJava) {
                    ongoing_scan.push("Extracting Javascript for " + req.body.domain); // add to ongoing scan array
                    exec('./tools/script.sh ' + req.body.domain + ' rootJava', { maxBuffer: 1024 * 20000 }, (err) => {
                        if (err) {
                            console.log(err);
                            //Removes from ongoing Scan
                            const index = ongoing_scan.indexOf("Extracting Javascript for " + req.body.domain);
                            if (index > -1) {
                                ongoing_scan.splice(index, 1);
                            }
                        }
                        else {
                            try {
                                var data = fs.readFileSync('./tools/' + req.body.domain + '_js.txt', { encoding: 'utf-8' }).split("\n");
                                db.save('Javascript', {
                                    "Javascript": data
                                }, (err) => {
                                    if (err) {
                                        console.log(err);
                                        //Removes from ongoing Scan
                                        const index = ongoing_scan.indexOf("Extracting Javascript for " + req.body.domain);
                                        if (index > -1) {
                                            ongoing_scan.splice(index, 1);
                                        }
                                    }
                                    else {
                                        exec('rm ./tools/' + req.body.domain + '_js.txt', (err) => {
                                            if (err) {
                                                console.log(err);
                                            }
                                        });
                                        //Removes from ongoing Scan
                                        const index = ongoing_scan.indexOf("Extracting Javascript for " + req.body.domain);
                                        if (index > -1) {
                                            ongoing_scan.splice(index, 1);
                                        }
                                    }
                                });
                            }
                            catch {
                                // if target data is not available in wayback then removes from ongoing scan
                                //Removes from ongoing Scan
                                const index = ongoing_scan.indexOf("Extracting Javascript for " + req.body.domain);
                                if (index > -1) {
                                    ongoing_scan.splice(index, 1);
                                }
                            }


                        }
                    });
                }

                //Include Subdomains
                if (req.body.subdomainsJava) {
                    ongoing_scan.push("Extracting Javascript for " + req.body.domain); // add to ongoing scan array
                    exec('./tools/script.sh ' + req.body.domain + ' subdomainJava', { maxBuffer: 1024 * 51200 }, (err) => {
                        if (err) {
                            console.log(err);
                            //Removes from ongoing Scan
                            const index = ongoing_scan.indexOf("Extracting Javascript for " + req.body.domain);
                            if (index > -1) {
                                ongoing_scan.splice(index, 1);
                            }
                        }
                        else {
                            try {
                                var data = fs.readFileSync('./tools/' + req.body.domain + '_jss.txt', { encoding: 'utf-8' }).split("\n");
                                db.save('Javascript_with_Subdomains', {
                                    "Javascript_with_Subdomains": data
                                }, (err) => {
                                    if (err) {
                                        console.log(err);
                                        //Removes from ongoing Scan
                                        const index = ongoing_scan.indexOf("Extracting Javascript for " + req.body.domain);
                                        if (index > -1) {
                                            ongoing_scan.splice(index, 1);
                                        }
                                    }
                                    else {
                                        exec('rm ./tools/' + req.body.domain + '_jss.txt', (err) => {
                                            if (err) {
                                                console.log(err);
                                            }
                                            //Removes from ongoing Scan
                                            const index = ongoing_scan.indexOf("Extracting Javascript for " + req.body.domain);
                                            if (index > -1) {
                                                ongoing_scan.splice(index, 1);
                                            }
                                        });
                                    }
                                });

                            }
                            catch {
                                // if target data is not available in wayback then removes from ongoing scan
                                //Removes from ongoing Scan
                                const index = ongoing_scan.indexOf("Extracting Javascript for " + req.body.domain);
                                if (index > -1) {
                                    ongoing_scan.splice(index, 1);
                                }
                            }

                        }
                    });
                }




                //================================== URL with Parameters Miner(ParamSpider) =============================

                if (req.body.parameters) {
                    ongoing_scan.push("Extracting Parameters for " + req.body.domain); // add to ongoing scan array
                    exec('./tools/script.sh ' + req.body.domain + ' parameters', { maxBuffer: 1024 * 20000 }, (err) => {
                        if (err) {
                            console.log(err);
                            //Removes from ongoing Scan
                            const index = ongoing_scan.indexOf("Extracting Parameters for " + req.body.domain);
                            if (index > -1) {
                                ongoing_scan.splice(index, 1);
                            }
                        }
                        else {
                            try {
                                var data = fs.readFileSync('./tools/ParamSpider/output/' + req.body.domain, { encoding: 'utf-8' }).split("\n");
                                db.save('URL_with_Parameters', {
                                    "URL_with_Parameters": data
                                }, (err) => {
                                    if (err) {
                                        console.log(err);
                                        //Removes from ongoing Scan
                                        const index = ongoing_scan.indexOf("Extracting Parameters for " + req.body.domain);
                                        if (index > -1) {
                                            ongoing_scan.splice(index, 1);
                                        }
                                    }
                                    //Removes from ongoing Scan
                                    const index = ongoing_scan.indexOf("Extracting Parameters for " + req.body.domain);
                                    if (index > -1) {
                                        ongoing_scan.splice(index, 1);
                                    }
                                });
                            }
                            catch {
                                //if target data is not available in wayback then Removes from ongoing Scan
                                const index = ongoing_scan.indexOf("Extracting Parameters for " + req.body.domain);
                                if (index > -1) {
                                    ongoing_scan.splice(index, 1);
                                }
                            }
                            exec('rm ./tools/ParamSpider/output/' + req.body.domain, (err) => {
                                if (err) {
                                    console.log(err);
                                }
                            });
                        }

                    });
                }

                if (req.body.subParameters) {
                    ongoing_scan.push("Extracting Parameters for " + req.body.domain); // add to ongoing scan array
                    exec('./tools/script.sh ' + req.body.domain + ' subParameters', { maxBuffer: 1024 * 20000 }, (err) => {
                        if (err) {
                            console.log(err);
                            //Removes from ongoing Scan
                            const index = ongoing_scan.indexOf("Extracting Parameters for " + req.body.domain);
                            if (index > -1) {
                                ongoing_scan.splice(index, 1);
                            }
                        }
                        else {
                            try {
                                var data = fs.readFileSync('./tools/ParamSpider/output/' + req.body.domain + 'sub', { encoding: 'utf-8' }).split("\n");
                                db.save('URL_with_Parameters_with_Subdomains', {
                                    "URL_with_Parameters_with_Subdomains": data
                                }, (err) => {
                                    if (err) {
                                        console.log(err);
                                        //Removes from ongoing Scan
                                        const index = ongoing_scan.indexOf("Extracting Parameters for " + req.body.domain);
                                        if (index > -1) {
                                            ongoing_scan.splice(index, 1);
                                        }
                                    }
                                    //Removes from ongoing Scan
                                    const index = ongoing_scan.indexOf("Extracting Parameters for " + req.body.domain);
                                    if (index > -1) {
                                        ongoing_scan.splice(index, 1);
                                    }
                                });
                            }
                            catch {
                                //if target data is not available in wayback then Removes from ongoing Scan
                                const index = ongoing_scan.indexOf("Extracting Parameters for " + req.body.domain);
                                if (index > -1) {
                                    ongoing_scan.splice(index, 1);
                                }
                            }

                            exec('rm ./tools/ParamSpider/output/' + req.body.domain + 'sub', (err) => {
                                if (err) {
                                    console.log(err);
                                }
                            });
                        }

                    });

                }



                //================================== Custom Wordlist =============================

                if (req.body.rootonly) {
                    ongoing_scan.push("Generating Custom Wordlist for " + req.body.domain); // add to ongoing scan array
                    exec('./tools/wordlist.sh ' + req.body.domain + ' root', { maxBuffer: 1024 * 102400 }, (err) => {
                        if (err) {
                            console.log(err);
                            //Removes from ongoing Scan
                            const index = ongoing_scan.indexOf("Generating Custom Wordlist for " + req.body.domain);
                            if (index > -1) {
                                ongoing_scan.splice(index, 1);
                            }
                        }
                        else {
                            try {
                                var data = fs.readFileSync('./tools/paths-' + req.body.domain + '.txt', { encoding: 'utf-8' }).split("\n");
                                db.save('custom_wordlist', {
                                    "custom_wordlist": data
                                }, (err) => {
                                    if (err) {
                                        console.log(err);
                                        //Removes from ongoing Scan
                                        const index = ongoing_scan.indexOf("Generating Custom Wordlist for " + req.body.domain);
                                        if (index > -1) {
                                            ongoing_scan.splice(index, 1);
                                        }
                                    }
                                    //Removes from ongoing Scan
                                    const index = ongoing_scan.indexOf("Generating Custom Wordlist for " + req.body.domain);
                                    if (index > -1) {
                                        ongoing_scan.splice(index, 1);
                                    }
                                });
                            }
                            catch {
                                //Removes from ongoing Scan
                                const index = ongoing_scan.indexOf("Generating Custom Wordlist for " + req.body.domain);
                                if (index > -1) {
                                    ongoing_scan.splice(index, 1);
                                }
                            }

                            exec('rm ./tools/paths-' + req.body.domain + '.txt', (err) => {
                                if (err) {
                                    console.log(err);
                                }
                            });

                        }

                    });

                }

                if (req.body.subdomain_word) {
                    ongoing_scan.push("Generating Custom Wordlist for " + req.body.domain); // add to ongoing scan array
                    exec('./tools/wordlist.sh ' + req.body.domain + ' subdomain', { maxBuffer: 1024 * 102400 }, (err) => {
                        if (err) {
                            console.log(err);
                            //Removes from ongoing Scan
                            const index = ongoing_scan.indexOf("Generating Custom Wordlist for " + req.body.domain);
                            if (index > -1) {
                                ongoing_scan.splice(index, 1);
                            }
                        }
                        else {
                            try {
                                var data = fs.readFileSync('./tools/paths-' + req.body.domain + '.txt', { encoding: 'utf-8' }).split("\n");
                                db.save('custom_wordlist', {
                                    "custom_wordlist": data
                                }, (err) => {
                                    if (err) {
                                        console.log(err);
                                        //Removes from ongoing Scan
                                        const index = ongoing_scan.indexOf("Generating Custom Wordlist for " + req.body.domain);
                                        if (index > -1) {
                                            ongoing_scan.splice(index, 1);
                                        }
                                    }
                                    //Removes from ongoing Scan
                                    const index = ongoing_scan.indexOf("Generating Custom Wordlist for " + req.body.domain);
                                    if (index > -1) {
                                        ongoing_scan.splice(index, 1);
                                    }
                                });
                            }
                            catch {
                                //Removes from ongoing Scan
                                const index = ongoing_scan.indexOf("Generating Custom Wordlist for " + req.body.domain);
                                if (index > -1) {
                                    ongoing_scan.splice(index, 1);
                                }
                            }

                            exec('rm ./tools/paths-' + req.body.domain + '.txt', (err) => {
                                if (err) {
                                    console.log(err);
                                }
                            });

                        }

                    });


                }


                //================================== CORS Misconfiguration =============================

                if (req.body.cors) {
                    ongoing_scan.push("Checking CORS for " + req.body.domain); // add to ongoing scan array
                    exec('./tools/script.sh ' + req.body.domain + ' cors', { maxBuffer: 1024 * 1200 }, (err) => {
                        if (err) {
                            console.log(err);
                            //Removes from ongoing Scan
                            const index = ongoing_scan.indexOf("Checking CORS for " + req.body.domain);
                            if (index > -1) {
                                ongoing_scan.splice(index, 1);
                            }
                        }
                        else {
                            var data = fs.readFileSync('./tools/Corsy/' + req.body.domain + '_cors.txt', { encoding: 'utf-8' });
                            db.save('CORS_misconfiguration', {
                                CORS_misconfiguration: data.split("\n")
                            }, (err) => {
                                if (err) {
                                    console.log(err);
                                    //Removes from ongoing Scan
                                    const index = ongoing_scan.indexOf("Checking CORS for " + req.body.domain);
                                    if (index > -1) {
                                        ongoing_scan.splice(index, 1);
                                    }
                                }
                                else {
                                    exec('rm ./tools/Corsy/' + req.body.domain + '_cors.txt', (err) => {
                                        if (err) {
                                            console.log(err);
                                        }
                                        //Removes from ongoing Scan
                                        const index = ongoing_scan.indexOf("Checking CORS for " + req.body.domain);
                                        if (index > -1) {
                                            ongoing_scan.splice(index, 1);
                                        }
                                    });
                                }
                            });
                        }
                    });

                }

                if (req.body.subdomain_cors) {
                    ongoing_scan.push("Checking CORS for " + req.body.domain); // add to ongoing scan array
                    exec('./tools/script.sh ' + req.body.domain + ' subdomainCors', { maxBuffer: 1024 * 1200 }, (err) => {
                        if (err) {
                            console.log(err);
                            //Removes from ongoing Scan
                            const index = ongoing_scan.indexOf("Checking CORS for " + req.body.domain);
                            if (index > -1) {
                                ongoing_scan.splice(index, 1);
                            }
                        }
                        else {
                            var data = fs.readFileSync('./tools/Corsy/' + req.body.domain + '_cors.txt', { encoding: 'utf-8' });
                            db.save('CORS_misconfiguration_on_subdomains', {
                                CORS_misconfiguration_on_subdomains: data.split("\n")
                            }, (err) => {
                                if (err) {
                                    console.log(err);
                                }
                                else {
                                    exec('rm ./tools/Corsy/' + req.body.domain + '_cors.txt', (err) => {
                                        if (err) {
                                            console.log(err);
                                        }
                                        //Removes from ongoing Scan
                                        const index = ongoing_scan.indexOf("Checking CORS for " + req.body.domain);
                                        if (index > -1) {
                                            ongoing_scan.splice(index, 1);
                                        }
                                    });
                                }
                            });
                        }
                    });

                }


                //================================ Templates Scan ====================================

                //files

                if (req.body.files && !req.body.template_subdomains) {
                    ongoing_scan.push("Template Scan [Files] on " + req.body.domain); // add to ongoing scan array
                    exec('echo https://www.' + req.body.domain + ' | nuclei -t ./tools/nuclei-templates/exposures/ -o ./tools/' + req.body.domain + "_files.txt", (err) => {
                        if (err) {
                            console.log(err);
                            //Removes from ongoing Scan
                            const index = ongoing_scan.indexOf("Template Scan [Files] on " + req.body.domain);
                            if (index > -1) {
                                ongoing_scan.splice(index, 1);
                            }
                        }
                        else {
                            var x = "Target is Not Vulnerable";
                            if (!fs.existsSync('./tools/' + req.body.domain + '_files.txt')) {
                                db.save('Files', {
                                    "Files": x.split("\n")
                                }, (err, res) => {
                                    if (err) {
                                        console.log(err);
                                        //Removes from ongoing Scan
                                        const index = ongoing_scan.indexOf("Template Scan [Files] on " + req.body.domain);
                                        if (index > -1) {
                                            ongoing_scan.splice(index, 1);
                                        }
                                    }
                                    //Removes from ongoing Scan
                                    const index = ongoing_scan.indexOf("Template Scan [Files] on " + req.body.domain);
                                    if (index > -1) {
                                        ongoing_scan.splice(index, 1);
                                    }
                                });
                            }
                            else {
                                var data = fs.readFileSync('./tools/' + req.body.domain + '_files.txt', { encoding: 'utf-8' }).split("\n");
                                db.save('Files', {
                                    "Files": data
                                }, (err, res) => {
                                    if (err) {
                                        console.log(err);
                                        //Removes from ongoing Scan
                                        const index = ongoing_scan.indexOf("Template Scan [Files] on " + req.body.domain);
                                        if (index > -1) {
                                            ongoing_scan.splice(index, 1);
                                        }
                                    }
                                });
                                exec('rm -f ./tools/' + req.body.domain + '_files.txt', (err) => {
                                    if (err) {
                                        console.log(err);
                                        //Removes from ongoing Scan
                                        const index = ongoing_scan.indexOf("Template Scan [Files] on " + req.body.domain);
                                        if (index > -1) {
                                            ongoing_scan.splice(index, 1);
                                        }
                                    }
                                });

                            }

                        }
                    }
                    );

                }

                //files with subdomains

                if (req.body.files && req.body.template_subdomains) {
                    ongoing_scan.push("Template Scan [Files] on " + req.body.domain); // add to ongoing scan array
                    async function getSubdomains() {
                        await db.get('valid_subdomains', (err, res) => {
                            res.valid_subdomains.forEach((element) => {
                                fs.appendFileSync('./tools/' + req.body.domain + '_files_subdomain.txt', element + ("\n"), { encoding: 'utf-8' });
                            });
                            async function scan_files() {
                                await exec('./tools/templates-scan.sh ' + req.body.domain + ' files', { maxBuffer: 1024 * 2200 }, (err) => {
                                    if (err) {
                                        console.log(err);
                                        //Removes from ongoing Scan
                                        const index = ongoing_scan.indexOf("Template Scan [Files] on " + req.body.domain);
                                        if (index > -1) {
                                            ongoing_scan.splice(index, 1);
                                        }
                                    }
                                    else {
                                        var data = fs.readFileSync('./tools/' + req.body.domain + '_subdomain_files.txt', { encoding: 'utf-8' }).split("\n");
                                        db.save('Files_on_Subdomains', {
                                            'Files_on_Subdomains': data
                                        }, (err) => {
                                            if (err) {
                                                console.log(err);
                                                //Removes from ongoing Scan
                                                const index = ongoing_scan.indexOf("Template Scan [Files] on " + req.body.domain);
                                                if (index > -1) {
                                                    ongoing_scan.splice(index, 1);
                                                }
                                            }
                                        });
                                        //Removes from ongoing Scan
                                        const index = ongoing_scan.indexOf("Template Scan [Files] on " + req.body.domain);
                                        if (index > -1) {
                                            ongoing_scan.splice(index, 1);
                                        }
                                        exec('rm -f ./tools/' + req.body.domain + '_subdomain_files.txt', (err) => {
                                            if (err) {
                                                console.log(err);
                                            }
                                        });
                                        exec('rm -f ./tools/' + req.body.domain + '_files_subdomain.txt', (err) => {
                                            if (err) {
                                                console.log(err);
                                            }
                                        });
                                    }
                                });
                            } scan_files();
                        });
                    }
                    getSubdomains();

                }

                //Panels

                if (req.body.panels && !req.body.template_subdomains) {
                    ongoing_scan.push("Template Scan [Panels] on " + req.body.domain); // add to ongoing scan array

                    exec('echo https://www.' + req.body.domain + '| nuclei -t ./tools/nuclei-templates/exposed-panels/ -o ./tools/' + req.body.domain + "_panels.txt", { maxBuffer: 1024 * 1200 }, (err) => {
                        if (err) {
                            console.log(err);
                            //Removes from ongoing Scan
                            const index = ongoing_scan.indexOf("Template Scan [Panels] on " + req.body.domain);
                            if (index > -1) {
                                ongoing_scan.splice(index, 1);
                            }
                        }
                        else {
                            var x = "Target is Not Vulnerable";
                            if (!fs.existsSync('./tools/' + req.body.domain + '_panels.txt')) {
                                db.save('Panels', {
                                    "Panels": x.split("\n")
                                }, (err, res) => {
                                    if (err) {
                                        console.log(err);
                                        //Removes from ongoing Scan
                                        const index = ongoing_scan.indexOf("Template Scan [Panels] on " + req.body.domain);
                                        if (index > -1) {
                                            ongoing_scan.splice(index, 1);
                                        }
                                    }
                                    //Removes from ongoing Scan
                                    const index = ongoing_scan.indexOf("Template Scan [Panels] on " + req.body.domain);
                                    if (index > -1) {
                                        ongoing_scan.splice(index, 1);
                                    }
                                });
                            }
                            else {
                                var data = fs.readFileSync('./tools/' + req.body.domain + '_panels.txt', { encoding: 'utf-8' }).split("\n");
                                db.save('Panels', {
                                    "Panels": data
                                }, (err, res) => {
                                    if (err) {
                                        console.log(err);
                                        //Removes from ongoing Scan
                                        const index = ongoing_scan.indexOf("Template Scan [Panels] on " + req.body.domain);
                                        if (index > -1) {
                                            ongoing_scan.splice(index, 1);
                                        }
                                    }
                                    //Removes from ongoing Scan
                                    const index = ongoing_scan.indexOf("Template Scan [Panels] on " + req.body.domain);
                                    if (index > -1) {
                                        ongoing_scan.splice(index, 1);
                                    }
                                });
                                exec('rm -f ./tools/' + req.body.domain + '_panels.txt', (err) => {
                                    if (err) {
                                        console.log(err);
                                    }
                                });

                            }

                        }
                    }
                    );

                }


                //Panels with subdomains

                if (req.body.panels && req.body.template_subdomains) {
                    ongoing_scan.push("Template Scan [Panels] on " + req.body.domain); // add to ongoing scan array
                    async function getSubdomains() {
                        await db.get('valid_subdomains', (err, res) => {
                            res.valid_subdomains.forEach((element) => {
                                fs.appendFileSync('./tools/' + req.body.domain + '_panels_subdomain.txt', element + ("\n"), { encoding: 'utf-8' });
                            });
                            async function scan_files() {
                                await exec('./tools/templates-scan.sh ' + req.body.domain + ' panels', { maxBuffer: 1024 * 2200 }, (err) => {
                                    if (err) {
                                        console.log(err);
                                        //Removes from ongoing Scan
                                        const index = ongoing_scan.indexOf("Template Scan [Panels] on " + req.body.domain);
                                        if (index > -1) {
                                            ongoing_scan.splice(index, 1);
                                        }
                                    }
                                    else {
                                        var data = fs.readFileSync('./tools/' + req.body.domain + '_subdomain_panels.txt', { encoding: 'utf-8' }).split("\n");
                                        db.save('Panels_on_Subdomains', {
                                            'Panels_on_Subdomains': data
                                        }, (err) => {
                                            if (err) {
                                                console.log(err);
                                                //Removes from ongoing Scan
                                                const index = ongoing_scan.indexOf("Template Scan [Panels] on " + req.body.domain);
                                                if (index > -1) {
                                                    ongoing_scan.splice(index, 1);
                                                }
                                            }
                                            //Removes from ongoing Scan
                                            const index = ongoing_scan.indexOf("Template Scan [Panels] on " + req.body.domain);
                                            if (index > -1) {
                                                ongoing_scan.splice(index, 1);
                                            }
                                        });
                                        exec('rm -f ./tools/' + req.body.domain + '_subdomain_panels.txt', (err) => {
                                            if (err) {
                                                console.log(err);
                                            }
                                        });
                                        exec('rm -f ./tools/' + req.body.domain + '_panels_subdomain.txt', (err) => {
                                            if (err) {
                                                console.log(err);
                                            }
                                        });
                                    }
                                });
                            } scan_files();
                        });
                    }
                    getSubdomains();

                }

                //Misconfigurations

                if (req.body.misconfigurations && !req.body.template_subdomains) {
                  
                    exec('echo https://www.' + req.body.domain + ' | nuclei -t ./tools/nuclei-templates/misconfiguration/ -o ./tools/' + req.body.domain + "_misconfigurations.txt", { maxBuffer: 1024 * 1200 }, (err) => {
                        if (err) {
                            console.log(err);
                        }
                        else {
                            var x = "Target is Not Vulnerable";
                            if (!fs.existsSync('./tools/' + req.body.domain + '_misconfigurations.txt')) {
                                db.save('Misconfigurations', {
                                    "Misconfigurations": x.split("\n")
                                }, (err, res) => {
                                    if (err) {
                                        console.log(err);
                                    }
                                });
                            }
                            else {
                                var data = fs.readFileSync('./tools/' + req.body.domain + '_misconfigurations.txt', { encoding: 'utf-8' }).split("\n");
                                db.save('Misconfigurations', {
                                    "Misconfigurations": data
                                }, (err, res) => {
                                    if (err) {
                                        console.log(err);
                                    }
                                });
                                exec('rm -f ./tools/' + req.body.domain + '_misconfigurations.txt', (err) => {
                                    if (err) {
                                        console.log(err);
                                    }
                                });

                            }

                        }
                    }
                    );

                }

                // Misconfigurations with subdomains

                if (req.body.misconfigurations && req.body.template_subdomains) {
                    async function getSubdomains() {
                        await db.get('valid_subdomains', (err, res) => {
                            res.valid_subdomains.forEach((element) => {
                                fs.appendFileSync('./tools/' + req.body.domain + '_misconfigurations_subdomain.txt', element + ("\n"), { encoding: 'utf-8' });
                            });
                            async function scan_files() {
                                await exec('./tools/templates-scan.sh ' + req.body.domain + ' misconfigurations', { maxBuffer: 1024 * 2200 }, (err) => {
                                    if (err) {
                                        console.log(err);
                                    }
                                    else {
                                        var data = fs.readFileSync('./tools/' + req.body.domain + '_subdomain_misconfigurations.txt', { encoding: 'utf-8' }).split("\n");
                                        db.save('Misconfigurations_on_Subdomains', {
                                            'Misconfigurations_on_Subdomains': data
                                        }, (err) => {
                                            if (err) {
                                                console.log(err);
                                            }
                                        });
                                        exec('rm -f ./tools/' + req.body.domain + '_subdomain_misconfigurations.txt', (err) => {
                                            if (err) {
                                                console.log(err);
                                            }
                                        });
                                        exec('rm -f ./tools/' + req.body.domain + '_misconfigurations_subdomain.txt', (err) => {
                                            if (err) {
                                                console.log(err);
                                            }
                                        });
                                    }
                                });
                            } scan_files();
                        });
                    }
                    getSubdomains();

                }

                //Technologies

                if (req.body.technologies && !req.body.template_subdomains) {
                    ongoing_scan.push("Template Scan [Tech] on " + req.body.domain); // add to ongoing scan array

                    exec('echo https://www.' + req.body.domain + ' | nuclei -t ./tools/nuclei-templates/technologies/ -o ./tools/' + req.body.domain + "_technologies.txt", { maxBuffer: 1024 * 1200 }, (err) => {
                        if (err) {
                            console.log(err);
                            //Removes from ongoing Scan
                            const index = ongoing_scan.indexOf("Template Scan [Tech] on " + req.body.domain);
                            if (index > -1) {
                                ongoing_scan.splice(index, 1);
                            }
                        }
                        else {
                            var x = "Target is Not Vulnerable";
                            if (!fs.existsSync('./tools/' + req.body.domain + '_technologies.txt')) {
                                db.save('Technology', {
                                    "Technology": x.split("\n")
                                }, (err, res) => {
                                    if (err) {
                                        console.log(err);
                                        //Removes from ongoing Scan
                                        const index = ongoing_scan.indexOf("Template Scan [Tech] on " + req.body.domain);
                                        if (index > -1) {
                                            ongoing_scan.splice(index, 1);
                                        }
                                    }
                                    //Removes from ongoing Scan
                                    const index = ongoing_scan.indexOf("Template Scan [Tech] on " + req.body.domain);
                                    if (index > -1) {
                                        ongoing_scan.splice(index, 1);
                                    }
                                });
                            }
                            else {
                                var data = fs.readFileSync('./tools/' + req.body.domain + '_technologies.txt', { encoding: 'utf-8' }).split("\n");
                                db.save('Technology', {
                                    "Technology": data
                                }, (err, res) => {
                                    if (err) {
                                        console.log(err);
                                        //Removes from ongoing Scan
                                        const index = ongoing_scan.indexOf("Template Scan [Tech] on " + req.body.domain);
                                        if (index > -1) {
                                            ongoing_scan.splice(index, 1);
                                        }
                                    }
                                    //Removes from ongoing Scan
                                    const index = ongoing_scan.indexOf("Template Scan [Tech] on " + req.body.domain);
                                    if (index > -1) {
                                        ongoing_scan.splice(index, 1);
                                    }
                                });
                                exec('rm -f ./tools/' + req.body.domain + '_technologies.txt', (err) => {
                                    if (err) {
                                        console.log(err);
                                    }
                                });

                            }

                        }
                    }
                    );

                }

                //Technologies with subdomains

                if (req.body.technologies && req.body.template_subdomains) {
                    ongoing_scan.push("Template Scan [Tech] on " + req.body.domain); // add to ongoing scan array
                    async function getSubdomains() {
                        await db.get('valid_subdomains', (err, res) => {
                            res.valid_subdomains.forEach((element) => {
                                fs.appendFileSync('./tools/' + req.body.domain + '_technologies_subdomain.txt', element + ("\n"), { encoding: 'utf-8' });
                            });
                            async function scan_files() {
                                await exec('./tools/templates-scan.sh ' + req.body.domain + ' technologies', { maxBuffer: 1024 * 2200 }, (err) => {
                                    if (err) {
                                        console.log(err);
                                        //Removes from ongoing Scan
                                        const index = ongoing_scan.indexOf("Template Scan [Tech] on " + req.body.domain);
                                        if (index > -1) {
                                            ongoing_scan.splice(index, 1);
                                        }
                                    }
                                    else {
                                        var data = fs.readFileSync('./tools/' + req.body.domain + '_subdomain_technologies.txt', { encoding: 'utf-8' }).split("\n");
                                        db.save('Technology_on_Subdomains', {
                                            'Technology_on_Subdomains': data
                                        }, (err) => {
                                            if (err) {
                                                console.log(err);
                                                //Removes from ongoing Scan
                                                const index = ongoing_scan.indexOf("Template Scan [Tech] on " + req.body.domain);
                                                if (index > -1) {
                                                    ongoing_scan.splice(index, 1);
                                                }
                                            }
                                            //Removes from ongoing Scan
                                            const index = ongoing_scan.indexOf("Template Scan [Tech] on " + req.body.domain);
                                            if (index > -1) {
                                                ongoing_scan.splice(index, 1);
                                            }
                                        });
                                        exec('rm -f ./tools/' + req.body.domain + '_subdomain_technologies.txt', (err) => {
                                            if (err) {
                                                console.log(err);
                                            }
                                        });
                                        exec('rm -f ./tools/' + req.body.domain + '_technologies_subdomain.txt', (err) => {
                                            if (err) {
                                                console.log(err);
                                            }
                                        });
                                    }
                                });
                            } scan_files();
                        });
                    }
                    getSubdomains();

                }


                //Vulnerabilities

                if (req.body.vulnerabilities && !req.body.template_subdomains) {
                    ongoing_scan.push("Template Scan [Vuln] on " + req.body.domain); // add to ongoing scan array

                    exec('echo https://www.' + req.body.domain + ' | nuclei -t ./tools/nuclei-templates/vulnerabilities/ -o ./tools/' + req.body.domain + "_vulnerabilities.txt", { maxBuffer: 1024 * 1200 }, (err) => {
                        if (err) {
                            console.log(err);
                            //Removes from ongoing Scan
                            const index = ongoing_scan.indexOf("Template Scan [Vuln] on " + req.body.domain);
                            if (index > -1) {
                                ongoing_scan.splice(index, 1);
                            }
                        }
                        else {
                            var x = "Target is Not Vulnerable";
                            if (!fs.existsSync('./tools/' + req.body.domain + '_vulnerabilities.txt')) {
                                db.save('Vulnerabilities', {
                                    "Vulnerabilities": x.split("\n")
                                }, (err, res) => {
                                    if (err) {
                                        console.log(err);
                                        //Removes from ongoing Scan
                                        const index = ongoing_scan.indexOf("Template Scan [Vuln] on " + req.body.domain);
                                        if (index > -1) {
                                            ongoing_scan.splice(index, 1);
                                        }
                                    }
                                    //Removes from ongoing Scan
                                    const index = ongoing_scan.indexOf("Template Scan [Vuln] on " + req.body.domain);
                                    if (index > -1) {
                                        ongoing_scan.splice(index, 1);
                                    }
                                });
                            }
                            else {
                                var data = fs.readFileSync('./tools/' + req.body.domain + '_vulnerabilities.txt', { encoding: 'utf-8' }).split("\n");
                                db.save('Vulnerabilities', {
                                    "Vulnerabilities": data
                                }, (err, res) => {
                                    if (err) {
                                        console.log(err);
                                        //Removes from ongoing Scan
                                        const index = ongoing_scan.indexOf("Template Scan [Vuln] on " + req.body.domain);
                                        if (index > -1) {
                                            ongoing_scan.splice(index, 1);
                                        }
                                    }
                                    //Removes from ongoing Scan
                                    const index = ongoing_scan.indexOf("Template Scan [Vuln] on " + req.body.domain);
                                    if (index > -1) {
                                        ongoing_scan.splice(index, 1);
                                    }
                                });
                                exec('rm -f ./tools/' + req.body.domain + '_vulnerabilities.txt', (err) => {
                                    if (err) {
                                        console.log(err);
                                    }
                                });

                            }

                        }
                    }
                    );

                }

                //Vulnerabilities with subdomains

                if (req.body.vulnerabilities && req.body.template_subdomains) {
                    ongoing_scan.push("Template Scan [Vuln] on " + req.body.domain); // add to ongoing scan array
                    async function getSubdomains() {
                        await db.get('valid_subdomains', (err, res) => {
                            res.valid_subdomains.forEach((element) => {
                                fs.appendFileSync('./tools/' + req.body.domain + '_vulnerabilities_subdomain.txt', element + ("\n"), { encoding: 'utf-8' });
                            });
                            async function scan_files() {
                                await exec('./tools/templates-scan.sh ' + req.body.domain + ' vulnerabilities', { maxBuffer: 1024 * 2200 }, (err) => {
                                    if (err) {
                                        console.log(err);
                                        //Removes from ongoing Scan
                                        const index = ongoing_scan.indexOf("Template Scan [Vuln] on " + req.body.domain);
                                        if (index > -1) {
                                            ongoing_scan.splice(index, 1);
                                        }
                                    }
                                    else {
                                        var data = fs.readFileSync('./tools/' + req.body.domain + '_subdomain_vulnerabilities.txt', { encoding: 'utf-8' }).split("\n");
                                        db.save('Vulnerabilities_on_Subdomains', {
                                            'Vulnerabilities_on_Subdomains': data
                                        }, (err) => {
                                            if (err) {
                                                console.log(err);
                                                //Removes from ongoing Scan
                                                const index = ongoing_scan.indexOf("Template Scan [Vuln] on " + req.body.domain);
                                                if (index > -1) {
                                                    ongoing_scan.splice(index, 1);
                                                }
                                            }
                                            //Removes from ongoing Scan
                                            const index = ongoing_scan.indexOf("Template Scan [Vuln] on " + req.body.domain);
                                            if (index > -1) {
                                                ongoing_scan.splice(index, 1);
                                            }
                                        });
                                        exec('rm -f ./tools/' + req.body.domain + '_subdomain_vulnerabilities.txt', (err) => {
                                            if (err) {
                                                console.log(err);
                                            }
                                        });
                                        exec('rm -f ./tools/' + req.body.domain + '_vulnerabilities_subdomain.txt', (err) => {
                                            if (err) {
                                                console.log(err);
                                            }
                                        });
                                    }
                                });
                            } scan_files();
                        });
                    }
                    getSubdomains();

                }



                //Tokens

                if (req.body.tokens && !req.body.template_subdomains) {
                    ongoing_scan.push("Template Scan [Token] on " + req.body.domain); // add to ongoing scan array

                    exec('echo https://www.' + req.body.domain + ' | nuclei -t ./tools/nuclei-templates/exposed-tokens/ -o ./tools/' + req.body.domain + "_tokens.txt", { maxBuffer: 1024 * 1200 }, (err) => {
                        if (err) {
                            console.log(err);
                            //Removes from ongoing Scan
                            const index = ongoing_scan.indexOf("Template Scan [Token] on " + req.body.domain);
                            if (index > -1) {
                                ongoing_scan.splice(index, 1);
                            }
                        }
                        else {
                            var x = "Target is Not Vulnerable";
                            if (!fs.existsSync('./tools/' + req.body.domain + '_tokens.txt')) {
                                db.save('Token', {
                                    "Token": x.split("\n")
                                }, (err, res) => {
                                    if (err) {
                                        console.log(err);
                                        //Removes from ongoing Scan
                                        const index = ongoing_scan.indexOf("Template Scan [Token] on " + req.body.domain);
                                        if (index > -1) {
                                            ongoing_scan.splice(index, 1);
                                        }
                                    }
                                });
                            }
                            else {
                                var data = fs.readFileSync('./tools/' + req.body.domain + '_tokens.txt', { encoding: 'utf-8' }).split("\n");
                                db.save('Token', {
                                    "Token": data
                                }, (err, res) => {
                                    if (err) {
                                        console.log(err);
                                        //Removes from ongoing Scan
                                        const index = ongoing_scan.indexOf("Template Scan [Token] on " + req.body.domain);
                                        if (index > -1) {
                                            ongoing_scan.splice(index, 1);
                                        }
                                    }
                                    //Removes from ongoing Scan
                                    const index = ongoing_scan.indexOf("Template Scan [Token] on " + req.body.domain);
                                    if (index > -1) {
                                        ongoing_scan.splice(index, 1);
                                    }
                                });
                                exec('rm -f ./tools/' + req.body.domain + '_tokens.txt', (err) => {
                                    if (err) {
                                        console.log(err);
                                    }
                                });

                            }

                        }
                    }
                    );

                }

                //Tokens with subdomains

                if (req.body.tokens && req.body.template_subdomains) {
                    ongoing_scan.push("Template Scan [Token] on " + req.body.domain); // add to ongoing scan array
                    async function getSubdomains() {
                        await db.get('valid_subdomains', (err, res) => {
                            res.valid_subdomains.forEach((element) => {
                                fs.appendFileSync('./tools/' + req.body.domain + '_tokens_subdomain.txt', element + ("\n"), { encoding: 'utf-8' });
                            });
                            async function scan_files() {
                                await exec('./tools/templates-scan.sh ' + req.body.domain + ' tokens', { maxBuffer: 1024 * 2200 }, (err) => {
                                    if (err) {
                                        console.log(err);
                                        //Removes from ongoing Scan
                                        const index = ongoing_scan.indexOf("Template Scan [Token] on " + req.body.domain);
                                        if (index > -1) {
                                            ongoing_scan.splice(index, 1);
                                        }
                                    }
                                    else {
                                        var data = fs.readFileSync('./tools/' + req.body.domain + '_subdomain_tokens.txt', { encoding: 'utf-8' }).split("\n");
                                        db.save('Tokens_on_Subdomains', {
                                            'Tokens_on_Subdomains': data
                                        }, (err) => {
                                            if (err) {
                                                console.log(err);
                                                //Removes from ongoing Scan
                                                const index = ongoing_scan.indexOf("Template Scan [Token] on " + req.body.domain);
                                                if (index > -1) {
                                                    ongoing_scan.splice(index, 1);
                                                }
                                            }
                                            //Removes from ongoing Scan
                                            const index = ongoing_scan.indexOf("Template Scan [Token] on " + req.body.domain);
                                            if (index > -1) {
                                                ongoing_scan.splice(index, 1);
                                            }
                                        });
                                        exec('rm -f ./tools/' + req.body.domain + '_subdomain_tokens.txt', (err) => {
                                            if (err) {
                                                console.log(err);
                                            }
                                        });
                                        exec('rm -f ./tools/' + req.body.domain + '_tokens_subdomain.txt', (err) => {
                                            if (err) {
                                                console.log(err);
                                            }
                                        });
                                    }
                                });
                            } scan_files();
                        });
                    }
                    getSubdomains();

                }

                //=================================== Secrets(API, Tokens) ================================

                if (req.body.secret) {
                    ongoing_scan.push("Searching Secrets for " + req.body.domain); // add to ongoing scan array
                    exec('python3 ./tools/SecretFinder/SecretFinder.py -i https://www.' + req.body.domain + ' -e -o cli', (err, stdout) => {
                        if (err) {
                            console.log(err);
                            //Removes from ongoing Scan
                            const index = ongoing_scan.indexOf("Searching Secrets for " + req.body.domain);
                            if (index > -1) {
                                ongoing_scan.splice(index, 1);
                            }
                        }
                        else {
                            db.save('Secrets', {
                                "Secrets": stdout.split('\n')
                            }, (err) => {
                                if (err) {
                                    console.log(err);
                                    //Removes from ongoing Scan
                                    const index = ongoing_scan.indexOf("Searching Secrets for " + req.body.domain);
                                    if (index > -1) {
                                        ongoing_scan.splice(index, 1);
                                    }
                                }
                                //Removes from ongoing Scan
                                const index = ongoing_scan.indexOf("Searching Secrets for " + req.body.domain);
                                if (index > -1) {
                                    ongoing_scan.splice(index, 1);
                                }
                            });

                        }

                    });

                }

                async function secret() {
                    if (req.body.subdomainsSecret) {
                        ongoing_scan.push("Searching Secrets for " + req.body.domain); // add to ongoing scan array
                        await db.get('valid_subdomains', (err, res) => {
                            if (err) {
                                console.log(err);
                                //Removes from ongoing Scan
                                const index = ongoing_scan.indexOf("Searching Secrets for " + req.body.domain);
                                if (index > -1) {
                                    ongoing_scan.splice(index, 1);
                                }
                            }
                            else {
                                res.valid_subdomains.forEach((row) => {
                                    fs.appendFileSync('./tools/' + req.body.domain + '_secret_subdomain.txt', row + ("\n"), { encoding: 'utf-8' });
                                });
                                db.get('Javascript_with_Subdomains', (err, res) => {
                                    if (err) {
                                        console.log(err);
                                        //Removes from ongoing Scan
                                        const index = ongoing_scan.indexOf("Searching Secrets for " + req.body.domain);
                                        if (index > -1) {
                                            ongoing_scan.splice(index, 1);
                                        }
                                    }
                                    else {
                                        res.Javascript_with_Subdomains.forEach((row) => {
                                            fs.appendFileSync('./tools/' + req.body.domain + '_secret_js.txt', row + ("\n"), { encoding: 'utf-8' });
                                        });
                                    }
                                });

                                async function secretloop() {
                                    await exec('./tools/script.sh ' + req.body.domain + ' secret', { maxBuffer: 1024 * 20000 }, (err) => {
                                        if (err) {
                                            console.log(err);
                                            //Removes from ongoing Scan
                                            const index = ongoing_scan.indexOf("Searching Secrets for " + req.body.domain);
                                            if (index > -1) {
                                                ongoing_scan.splice(index, 1);
                                            }
                                        }
                                        else {
                                            var data = fs.readFileSync('./tools/' + req.body.domain + '_secret.txt', { encoding: 'utf-8' }).split("\n");
                                            db.save('Secrets_on_Subdomains', {
                                                "Secrets_on_Subdomains": data
                                            }, (err) => {
                                                if (err) {
                                                    console.log(err);
                                                    //Removes from ongoing Scan
                                                    const index = ongoing_scan.indexOf("Searching Secrets for " + req.body.domain);
                                                    if (index > -1) {
                                                        ongoing_scan.splice(index, 1);
                                                    }
                                                }
                                                //Removes from ongoing Scan
                                                const index = ongoing_scan.indexOf("Searching Secrets for " + req.body.domain);
                                                if (index > -1) {
                                                    ongoing_scan.splice(index, 1);
                                                }
                                            });
                                            exec('rm -f ./tools/' + req.body.domain + '_secret.txt', (err) => {
                                                if (err) {
                                                    console.log(err);
                                                }
                                            });
                                        }
                                    });

                                } secretloop();
                            }

                        });
                    }
                } secret();



                //=================================== Directory/Files Bruteforce ================================


                //Fuzz for Critical Files
                if (req.body.critical && !req.body.subdomain_fuzz) {
                    ongoing_scan.push("Fuzzing for Critical Files on" + req.body.domain); // add to ongoing scan array
                    exec('./tools/bruteforce.sh critical ' + req.body.domain, { maxBuffer: 1024 * 1200 }, (err) => {
                        if (err) {
                            console.log(err);
                            //Removes from ongoing Scan
                            const index = ongoing_scan.indexOf("Fuzzing for Critical Files on" + req.body.domain);
                            if (index > -1) {
                                ongoing_scan.splice(index, 1);
                            }
                        }
                        else {
                            var data = fs.readFileSync('./tools/' + req.body.domain + '_critical.txt', { encoding: 'utf-8' }).split('\n');
                            db.save('Critical_Files', {
                                Critical_Files: data
                            }, (err) => {
                                if (err) {
                                    console.log(err);
                                    //Removes from ongoing Scan
                                    const index = ongoing_scan.indexOf("Fuzzing for Critical Files on" + req.body.domain);
                                    if (index > -1) {
                                        ongoing_scan.splice(index, 1);
                                    }
                                }
                                else {
                                    exec('rm ./tools/' + req.body.domain + '_critical.txt', (err) => {
                                        if (err) {
                                            console.log(err);
                                        }
                                    });
                                    //Removes from ongoing Scan
                                    const index = ongoing_scan.indexOf("Fuzzing for Critical Files on" + req.body.domain);
                                    if (index > -1) {
                                        ongoing_scan.splice(index, 1);
                                    }
                                }
                            });
                        }
                    });

                }

                //Fuzz for Directory
                if (req.body.directory && !req.body.subdomain_fuzz) {
                    ongoing_scan.push("Fuzzing for Directory on  " + req.body.domain); // add to ongoing scan array
                    exec('./tools/bruteforce.sh directory ' + req.body.domain, { maxBuffer: 1024 * 1200 }, (err) => {
                        if (err) {
                            console.log(err);
                            //Removes from ongoing Scan
                            const index = ongoing_scan.indexOf("Fuzzing for Directory on  " + req.body.domain);
                            if (index > -1) {
                                ongoing_scan.splice(index, 1);
                            }
                        }
                        else {
                            var data = fs.readFileSync('./tools/' + req.body.domain + '_directory.txt', { encoding: 'utf-8' }).split('\n');
                            db.save('Directory_Bruteforce', {
                                Directory_Bruteforce: data
                            }, (err) => {
                                if (err) {
                                    console.log(err);
                                    //Removes from ongoing Scan
                                    const index = ongoing_scan.indexOf("Fuzzing for Directory on  " + req.body.domain);
                                    if (index > -1) {
                                        ongoing_scan.splice(index, 1);
                                    }
                                }
                                else {
                                    exec('rm ./tools/' + req.body.domain + '_directory.txt', (err) => {
                                        if (err) {
                                            console.log(err);
                                        }
                                    });
                                    //Removes from ongoing Scan
                                    const index = ongoing_scan.indexOf("Fuzzing for Directory on  " + req.body.domain);
                                    if (index > -1) {
                                        ongoing_scan.splice(index, 1);
                                    }
                                }
                            });
                        }
                    });

                }

                //Fuzz critical files on subdomain
                if (req.body.subdomain_fuzz) {
                    if (req.body.critical) {
                        ongoing_scan.push("Fuzzing for Critical Files on" + req.body.domain); // add to ongoing scan array
                        async function critical() {
                            await db.get('valid_subdomains', (err, res) => {
                                if (err) {
                                    console.log(err);
                                    //Removes from ongoing Scan
                                    const index = ongoing_scan.indexOf("Fuzzing for Critical Files on" + req.body.domain);
                                    if (index > -1) {
                                        ongoing_scan.splice(index, 1);
                                    }
                                }
                                else {
                                    res.valid_subdomains.forEach((element) => {
                                        fs.appendFileSync('./tools/' + req.body.domain + '_critical_subdomain.txt', element + ("\n"), { encoding: 'utf-8' });
                                    });

                                    async function criticalRead() {
                                        await exec('./tools/bruteforce.sh subdomain_critical ' + req.body.domain, { maxBuffer: 1024 * 20200 }, (err) => {
                                            if (err) {
                                                console.log(err);
                                                //Removes from ongoing Scan
                                                const index = ongoing_scan.indexOf("Fuzzing for Critical Files on" + req.body.domain);
                                                if (index > -1) {
                                                    ongoing_scan.splice(index, 1);
                                                }
                                            }
                                            else {
                                                var data = fs.readFileSync('./tools/' + req.body.domain + '_subdomain_critical.txt', { encoding: 'utf-8' }).split("\n");
                                                db.save('Critical_Files_on_Subdomains', {
                                                    "Critical_Files_on_Subdomains": data
                                                }, (err) => {
                                                    if (err) {
                                                        console.log(err);
                                                        //Removes from ongoing Scan
                                                        const index = ongoing_scan.indexOf("Fuzzing for Critical Files on" + req.body.domain);
                                                        if (index > -1) {
                                                            ongoing_scan.splice(index, 1);
                                                        }
                                                    }
                                                    //Removes from ongoing Scan
                                                    const index = ongoing_scan.indexOf("Fuzzing for Critical Files on" + req.body.domain);
                                                    if (index > -1) {
                                                        ongoing_scan.splice(index, 1);
                                                    }
                                                });
                                                exec('rm -f ./tools/' + req.body.domain + '_subdomain_critical.txt', (err) => {
                                                    if (err) {
                                                        console.log(err);
                                                    }
                                                });
                                                exec('rm -f ./tools/' + req.body.domain + '_critical_subdomain.txt', (err) => {
                                                    if (err) {
                                                        console.log(err);
                                                    }
                                                });
                                            }
                                        });

                                    } criticalRead();
                                }
                            });


                        } critical();
                    }
                }

                //Fuzz for Directory on subdomain
                if (req.body.subdomain_fuzz) {
                    if (req.body.directory) {
                        ongoing_scan.push("Fuzzing for Directory on  " + req.body.domain); // add to ongoing scan array
                        async function directory() {
                            await db.get('valid_subdomains', (err, res) => {
                                if (err) {
                                    console.log(err);
                                    //Removes from ongoing Scan
                                    const index = ongoing_scan.indexOf("Fuzzing for Directory on  " + req.body.domain);
                                    if (index > -1) {
                                        ongoing_scan.splice(index, 1);
                                    }
                                }
                                else {
                                    res.valid_subdomains.forEach((element) => {
                                        fs.appendFileSync('./tools/' + req.body.domain + '_directory_subdomain.txt', element + ("\n"), { encoding: 'utf-8' });
                                    });

                                    async function criticalRead() {
                                        await exec('./tools/bruteforce.sh subdomain_directory ' + req.body.domain, { maxBuffer: 1024 * 20000 }, (err) => {
                                            if (err) {
                                                console.log(err);
                                                //Removes from ongoing Scan
                                                const index = ongoing_scan.indexOf("Fuzzing for Directory on  " + req.body.domain);
                                                if (index > -1) {
                                                    ongoing_scan.splice(index, 1);
                                                }
                                            }
                                            else {
                                                var data = fs.readFileSync('./tools/' + req.body.domain + '_subdomain_directory.txt', { encoding: 'utf-8' }).split("\n");
                                                db.save('Directory_BruteForce_on_Subdomains', {
                                                    "Directory_BruteForce_on_Subdomains": data
                                                }, (err) => {
                                                    if (err) {
                                                        console.log(err);
                                                        //Removes from ongoing Scan
                                                        const index = ongoing_scan.indexOf("Fuzzing for Directory on  " + req.body.domain);
                                                        if (index > -1) {
                                                            ongoing_scan.splice(index, 1);
                                                        }
                                                    }
                                                    //Removes from ongoing Scan
                                                    const index = ongoing_scan.indexOf("Fuzzing for Directory on  " + req.body.domain);
                                                    if (index > -1) {
                                                        ongoing_scan.splice(index, 1);
                                                    }
                                                });
                                                exec('rm -f ./tools/' + req.body.domain + '_subdomain_directory.txt', (err) => {
                                                    if (err) {
                                                        console.log(err);
                                                    }
                                                });
                                                exec('rm -f ./tools/' + req.body.domain + '_directory_subdomain.txt', (err) => {
                                                    if (err) {
                                                        console.log(err);
                                                    }
                                                });
                                            }
                                        });

                                    } criticalRead();
                                }
                            });


                        } directory();
                    }
                }

                //Fuzzing with Custom Generated Wordlist

                if (req.body.customWordlist && !req.body.subdomain_fuzz) {
                    ongoing_scan.push("Fuzzing with Custom Wordlist on  " + req.body.domain); // add to ongoing scan array
                    async function WordList() {
                        await db.get("custom_wordlist", (err, res) => {
                            if (err) {
                                console.log(err);
                                //Removes from ongoing Scan
                                const index = ongoing_scan.indexOf("Fuzzing with Custom Wordlist on  " + req.body.domain);
                                if (index > -1) {
                                    ongoing_scan.splice(index, 1);
                                }
                            }
                            else {
                                res.custom_wordlist.forEach((element) => {
                                    fs.appendFileSync('./tools/' + req.body.domain + '_custom_wordlist.txt', element + ("\n"), { encoding: 'utf-8' });
                                });
                                async function customBruteforce() {
                                    await exec('./tools/bruteforce.sh customWordlist ' + req.body.domain, { maxBuffer: 1024 * 20000 }, (err) => {
                                        if (err) {
                                            console.log(err);
                                            //Removes from ongoing Scan
                                            const index = ongoing_scan.indexOf("Fuzzing with Custom Wordlist on  " + req.body.domain);
                                            if (index > -1) {
                                                ongoing_scan.splice(index, 1);
                                            }
                                        }
                                        else {
                                            try {
                                                var data = fs.readFileSync('./tools/' + req.body.domain + '_custom.txt', { encoding: 'utf-8' }).split("\n");
                                            }
                                            catch {
                                                //Removes from ongoing Scan if scan started with no  generated wordlist
                                                const index = ongoing_scan.indexOf("Fuzzing with Custom Wordlist on  " + req.body.domain);
                                                if (index > -1) {
                                                    ongoing_scan.splice(index, 1);
                                                }
                                            }

                                            db.save('Custom_Wordlist_Bruteforce', {
                                                "Custom_Wordlist_Bruteforce": data
                                            }, (err) => {
                                                if (err) {
                                                    console.log(err);
                                                    //Removes from ongoing Scan
                                                    const index = ongoing_scan.indexOf("Fuzzing with Custom Wordlist on  " + req.body.domain);
                                                    if (index > -1) {
                                                        ongoing_scan.splice(index, 1);
                                                    }
                                                }
                                                //Removes from ongoing Scan
                                                const index = ongoing_scan.indexOf("Fuzzing with Custom Wordlist on  " + req.body.domain);
                                                if (index > -1) {
                                                    ongoing_scan.splice(index, 1);
                                                }
                                            });
                                            exec('rm -f ./tools/' + req.body.domain + '_custom.txt', (err) => {
                                                if (err) {
                                                    console.log(err);
                                                }
                                            });

                                        }
                                    });
                                } customBruteforce();
                            }
                        });
                    } WordList();
                }

                //===================================== Subdomain Takeover ==================================

                if (req.body.takeover) {
                    ongoing_scan.push("Subdomain Takeover for  " + req.body.domain); // add to ongoing scan array
                    exec('./tools/takeover.sh takeover ' + req.body.domain, { maxBuffer: 1024 * 4200 }, (err) => {
                        if (err) {
                            console.log(err);
                        }
                        else {
                            var data = fs.readFileSync('./tools/' + req.body.domain + '_vuln.txt', { encoding: 'utf-8' }).split("\n");
                            //Save result in DB if target is vulnerable
                            if (data[0].search("Vulnerable") > 0) {
                                db.save("Subdomain_Takeover", {
                                    "Subdomains_Takeover": data
                                }, (err) => {
                                    if (err) {
                                        console.log(err);
                                        //Removes from ongoing Scan
                                        const index = ongoing_scan.indexOf("Subdomain Takeover for  " + req.body.domain);
                                        if (index > -1) {
                                            ongoing_scan.splice(index, 1);
                                        }
                                    }
                                    else {
                                        exec('rm -f ./tools/' + req.body.domain + '_vuln.txt', (err) => {
                                            if (err) {
                                                console.log(err);
                                            }
                                        });
                                        //Removes from ongoing Scan
                                        const index = ongoing_scan.indexOf("Subdomain Takeover for  " + req.body.domain);
                                        if (index > -1) {
                                            ongoing_scan.splice(index, 1);
                                        }

                                    }
                                });
                            }
                            else {
                                //if not vulnerable then removes file from system
                                exec('rm -f ./tools/' + req.body.domain + '_vuln.txt', (err) => {
                                    if (err) {
                                        console.log(err);
                                    }
                                });
                                //Removes from ongoing Scan
                                const index = ongoing_scan.indexOf("Subdomain Takeover for  " + req.body.domain);
                                if (index > -1) {
                                    ongoing_scan.splice(index, 1);
                                }
                            }
                        }
                    });
                }


                //===================================== CRLF Scan ==================================
                //CRLF on domain only
                if (req.body.crlf) {
                    ongoing_scan.push("CRLF Scan on " + req.body.domain); // add to ongoing scan array
                    exec("crlf scan -u https://" + req.body.domain, (err, stdout) => {
                        if (err) {
                            console.log(err);

                        }
                        else {
                            var data = stdout.split("\n");
                            //saves result only if target is vulnerable
                            if (data[data.length - 2] != "No CRLF injection detected...") {
                                db.save("CRLF", { CRLF: "Vulnerable to CRLF Injection" }, (err) => {
                                    if (err) {
                                        console.log(err);
                                    }
                                });
                            }
                            //Removes from ongoing Scan
                            const index = ongoing_scan.indexOf("CRLF Scan on " + req.body.domain);
                            if (index > -1) {
                                ongoing_scan.splice(index, 1);
                            }
                        }
                    });
                }

                //CRLF on subdomains
                if (req.body.subdomain_crlf) {
                    ongoing_scan.push("CRLF Scan on " + req.body.domain); // add to ongoing scan array
                    async function crlf() {
                        await db.get("valid_subdomains", (err, res) => {
                            if (err) {
                                console.log(err);
                                //Removes from ongoing Scan
                                const index = ongoing_scan.indexOf("CRLF Scan on " + req.body.domain);
                                if (index > -1) {
                                    ongoing_scan.splice(index, 1);
                                }
                            }
                            else {
                                res.valid_subdomains.forEach((element) => {
                                    async function check() {
                                        await exec("crlf scan -u " + element, { maxBuffer: 1024 * 9200 }, (err, stdout) => {
                                            if (err) {
                                                console.log(err);
                                                //Removes from ongoing Scan
                                                const index = ongoing_scan.indexOf("CRLF Scan on " + req.body.domain);
                                                if (index > -1) {
                                                    ongoing_scan.splice(index, 1);
                                                }
                                            }
                                            else {
                                                var data = stdout.split("\n");
                                                console.log(data[data.length - 2]);
                                                //saves result only if target is vulnerable
                                                if (data[data.length - 2] != "No CRLF injection detected...") {
                                                    db.save("CRLF", { CRLF: "Vulnerable to CRLF Injection" }, (err) => {
                                                        if (err) {
                                                            console.log(err);
                                                        }
                                                    });
                                                }
                                                //Removes from ongoing Scan
                                                const index = ongoing_scan.indexOf("CRLF Scan on " + req.body.domain);
                                                if (index > -1) {
                                                    ongoing_scan.splice(index, 1);
                                                }
                                            }
                                        });
                                    } check();
                                });
                            }
                        });

                    } crlf();
                }


                //================================ Linkfinder to find Links in JS ==========================

                if (req.body.linkfinder) {
                    ongoing_scan.push("Finding Links for " + req.body.domain); // add to ongoing scan array
                    async function linkfinder() {
                        await db.get("Javascript", (err, res) => {
                            if (err) {
                                console.log(err);
                                //Removes from ongoing Scan
                                const index = ongoing_scan.indexOf("Finding Links for " + req.body.domain);
                                if (index > -1) {
                                    ongoing_scan.splice(index, 1);
                                }
                            }
                            else {
                                res.Javascript.forEach((element) => {
                                    fs.appendFileSync('./tools/LinkFinder/' + req.body.domain + '_jss.txt', element + ("\n"), { encoding: 'utf-8' });
                                });
                                async function read() {
                                    await exec('./tools/LinkFinder/links.sh linkfinder ' + req.body.domain, { maxBuffer: 1024 * 9200 }, (err) => {
                                        if (err) {
                                            console.log(err);
                                            const index = ongoing_scan.indexOf("Finding Links for " + req.body.domain);
                                            if (index > -1) {
                                                ongoing_scan.splice(index, 1);
                                            }
                                        }

                                        else {
                                            try {
                                                var data = fs.readFileSync('./tools/LinkFinder/' + req.body.domain + '_links.txt', { encoding: 'utf-8' }).split("\n");
                                            }
                                            catch {
                                                //renoves from ongoing scan if no JS is found
                                                const index = ongoing_scan.indexOf("Finding Links for " + req.body.domain);
                                                if (index > -1) {
                                                    ongoing_scan.splice(index, 1);
                                                }
                                            }
                                            db.save('Links_in_JS', {
                                                "Links_in_JS": data
                                            }, (err, res) => {
                                                if (err) {
                                                    console.log(err);
                                                    const index = ongoing_scan.indexOf("Finding Links for " + req.body.domain);
                                                    if (index > -1) {
                                                        ongoing_scan.splice(index, 1);
                                                    }
                                                }
                                                else {
                                                    exec('rm -f ./tools/LinkFinder/' + req.body.domain + '_links.txt', (err) => {
                                                        if (err) {
                                                            console.log(err);
                                                        }
                                                    });
                                                    const index = ongoing_scan.indexOf("Finding Links for " + req.body.domain);
                                                    if (index > -1) {
                                                        ongoing_scan.splice(index, 1);
                                                    }
                                                }
                                            });

                                        }

                                    });
                                } read();

                            }
                        });
                    } linkfinder();
                }


                // Linkfinder on subdomains Javascript

                if (req.body.subdomain_links) {
                    ongoing_scan.push("Finding Links for " + req.body.domain); // add to ongoing scan array
                    async function linkfinders() {
                        await db.get("Javascript_with_Subdomains", (err, res) => {
                            if (err) {
                                console.log(err);
                                const index = ongoing_scan.indexOf("Finding Links for " + req.body.domain);
                                if (index > -1) {
                                    ongoing_scan.splice(index, 1);
                                }
                            }
                            else {
                                res.Javascript_with_Subdomains.forEach((element) => {
                                    fs.appendFileSync('./tools/LinkFinder/' + req.body.domain + '_Subjss.txt', element + ("\n"), { encoding: 'utf-8' });
                                });
                                async function read() {
                                    await exec('./tools/LinkFinder/links.sh subdomains ' + req.body.domain, { maxBuffer: 1024 * 2200 }, (err) => {
                                        if (err) {
                                            console.log(err);
                                            const index = ongoing_scan.indexOf("Finding Links for " + req.body.domain);
                                            if (index > -1) {
                                                ongoing_scan.splice(index, 1);
                                            }
                                        }

                                        else {
                                            try {
                                                var data = fs.readFileSync('./tools/LinkFinder/' + req.body.domain + '_Sublinks.txt', { encoding: 'utf-8' }).split("\n");
                                            }
                                            catch {
                                                //renoves from ongoing scan if no JS is found
                                                const index = ongoing_scan.indexOf("Finding Links for " + req.body.domain);
                                                if (index > -1) {
                                                    ongoing_scan.splice(index, 1);
                                                }
                                            }
                                            db.save('Links_in_JS_with_Subdomains', {
                                                "Links_in_JS_with_Subdomains": data
                                            }, (err, res) => {
                                                if (err) {
                                                    console.log(err);
                                                    const index = ongoing_scan.indexOf("Finding Links for " + req.body.domain);
                                                    if (index > -1) {
                                                        ongoing_scan.splice(index, 1);
                                                    }
                                                }
                                                else {
                                                    exec('rm -f ./tools/LinkFinder/' + req.body.domain + '_Sublinks.txt', (err) => {
                                                        if (err) {
                                                            console.log(err);
                                                        }
                                                    });
                                                    const index = ongoing_scan.indexOf("Finding Links for " + req.body.domain);
                                                    if (index > -1) {
                                                        ongoing_scan.splice(index, 1);
                                                    }
                                                }
                                            });

                                        }

                                    });
                                } read();

                            }
                        });
                    } linkfinders();
                }


                //================================ Favicon Hash Generator with FavFreak ==========================
                if (req.body.favHash) {
                    ongoing_scan.push("Favicon Hash for " + req.body.domain); // add to ongoing scan array
                    exec('cd ./tools/FavFreak/ && subfinder -d ' + req.body.domain + ' -silent | httpx -silent | python3 favfreak.py -o ' + req.body.domain, { maxBuffer: 1024 * 4000 }, (err) => {
                        if (err) {
                            console.log(err);
                            //Removes from ongoing Scan
                            const index = ongoing_scan.indexOf("Favicon Hash for " + req.body.domain);
                            if (index > -1) {
                                ongoing_scan.splice(index, 1);
                            }
                        }
                        else {
                            exec('cd ./tools/FavFreak/ && ls ./' + req.body.domain, (err, stdout) => {
                                if (err) {
                                    console.log(err);
                                    //Removes from ongoing Scan
                                    const index = ongoing_scan.indexOf("Favicon Hash for " + req.body.domain);
                                    if (index > -1) {
                                        ongoing_scan.splice(index, 1);
                                    }
                                }
                                else {
                                    db.save('Favicon_Hash', { Favicon_Hash: (stdout.replace(/\.txt/g, "")).split("\n") }, (err) => {
                                        if (err) {
                                            console.log(err);
                                            //Removes from ongoing Scan
                                            const index = ongoing_scan.indexOf("Favicon Hash for " + req.body.domain);
                                            if (index > -1) {
                                                ongoing_scan.splice(index, 1);
                                            }
                                        }
                                        else {
                                            exec('rm -r ./tools/FavFreak/' + req.body.domain, (err) => {
                                                if (err) {
                                                    console.log(err);
                                                }
                                            });
                                            //Removes from ongoing Scan
                                            const index = ongoing_scan.indexOf("Favicon Hash for " + req.body.domain);
                                            if (index > -1) {
                                                ongoing_scan.splice(index, 1);
                                            }
                                        }
                                    });
                                }
                            });
                        }
                    });

                }

                //================================ Github Dorks ==========================

                //Github Dorks with domain search
                if (req.body.githubDomain) {
                    ongoing_scan.push("Github Dork for " + req.body.domain); // add to ongoing scan array
                    exec('cd ./tools/GitDorker/ && python3 GitDorker.py -tf ./tf/TOKENSFILE -e 3 -q ' + req.body.domain + ' -d ./Dorks/alldorksv2.txt -o ' + req.body.domain + ' && python3 csv2json.py ' + req.body.domain + '_gh_dorks.csv ' + req.body.domain + '.json && rm ' + req.body.domain + '_gh_dorks.csv', { maxBuffer: 1024 * 1024 }, (err) => {
                        if (err) {
                            console.log(err);
                            //Removes from ongoing Scan
                            const index = ongoing_scan.indexOf("Github Dork for " + req.body.domain);
                            if (index > -1) {
                                ongoing_scan.splice(index, 1);
                            }
                        }
                        else {
                            var data = fs.readFileSync('./tools/GitDorker/' + req.body.domain + '.json', { encoding: 'utf-8' });
                            var obj = JSON.parse(data);
                            db.save('Github_Dorks_with_Domain', {
                                Github_Dorks_with_Domain: obj
                            }, (err) => {
                                if (err) {
                                    console.log(err);
                                    //Removes from ongoing Scan
                                    const index = ongoing_scan.indexOf("Github Dork for " + req.body.domain);
                                    if (index > -1) {
                                        ongoing_scan.splice(index, 1);
                                    }
                                }
                                else {
                                    exec('rm ./tools/GitDorker/' + req.body.domain + '.json', (err) = {
                                        if(err) {
                                            console.log(err);

                                        }
                                    });
                                    const index = ongoing_scan.indexOf("Github Dork for " + req.body.domain);
                                    if (index > -1) {
                                        ongoing_scan.splice(index, 1);
                                    }
                                }
                            });
                        }
                    });

                }


                //Github Dorks with organisation search query
                if (req.body.githubOrg) {
                    ongoing_scan.push("Github Dork for " + req.body.domain); // add to ongoing scan array
                    exec('cd ./tools/GitDorker/ && python3 GitDorker.py -tf ./tf/TOKENSFILE -e 3 -org ' + (req.body.domain).split('.')[0] + ' -d ./Dorks/alldorksv2.txt -o ' + req.body.domain + ' && python3 csv2json.py ' + req.body.domain + '_gh_dorks.csv ' + req.body.domain + '.json && rm ' + req.body.domain + '_gh_dorks.csv', { maxBuffer: 1024 * 1024 }, (err) => {
                        if (err) {
                            console.log(err);
                            //Removes from ongoing Scan
                            const index = ongoing_scan.indexOf("Github Dork for " + req.body.domain);
                            if (index > -1) {
                                ongoing_scan.splice(index, 1);
                            }
                        }
                        else {
                            var data = fs.readFileSync('./tools/GitDorker/' + req.body.domain + '.json', { encoding: 'utf-8' });
                            var obj = JSON.parse(data);
                            db.save('Github_Dorks_with_org', {
                                Github_Dorks_with_org: obj
                            }, (err) => {
                                if (err) {
                                    console.log(err);
                                    //Removes from ongoing Scan
                                    const index = ongoing_scan.indexOf("Github Dork for " + req.body.domain);
                                    if (index > -1) {
                                        ongoing_scan.splice(index, 1);
                                    }
                                }
                                else {
                                    exec('rm ./tools/GitDorker/' + req.body.domain + '.json', (err) = {
                                        if(err) {
                                            console.log(err);

                                        }
                                    });
                                    const index = ongoing_scan.indexOf("Github Dork for " + req.body.domain);
                                    if (index > -1) {
                                        ongoing_scan.splice(index, 1);
                                    }
                                }
                            });
                        }
                    });

                }



            }

            //Main Function End Here

        }
    });

});



//=================================== Get Stored Result ==================================

//shows target name in home page

app.get('/result/', (req, res) => {
    jwt.verify(req.cookies.auth, 'fIskNyRbdGmdaekbMSRlAkU5RIJc6V7I', (err) => {
        if (err) {
            res.status(403).send("You're not authorized to use this framework!");
        }
        else {
            exec('curl -X GET http://admin:hackwithme@127.0.0.1:5984/_all_dbs', (err, val) => { //get list of all database
                if (err) {
                    console.log(err);
                }
                else {
                    res.render('result', {
                        data: JSON.parse(val)
                    });
                }
            });
        }
    });


});


//==================================== Fetch target data values from database ======================================


app.post('/target/', urlencodedParser, (req, res) => {

    jwt.verify(req.cookies.auth, 'fIskNyRbdGmdaekbMSRlAkU5RIJc6V7I', (err) => {
        if (err) {
            res.status(403).send("You're not authorized to use this framework!");
        }
        else {
            exec('curl -X GET http://admin:hackwithme@127.0.0.1:5984/' + req.body.check + '/_all_docs', (err, val) => { //get list of all documents of target
                if (err) {
                    console.log(err);
                }
                else {
                    res.render('target', {
                        data: JSON.parse(val),
                        domainName: req.body.check
                    });
                }
            });
        }
    });

});


//============================ Fetch Documents Value ===================================

app.post('/show-value/', urlencodedParser, (req, res) => {

    jwt.verify(req.cookies.auth, 'fIskNyRbdGmdaekbMSRlAkU5RIJc6V7I', (err) => {
        if (err) {
            res.status(403).send("You're not authorized to use this framework!");
        }
        else {

            var connection = new (cradle.Connection)('http://127.0.0.1', 5984, {
                auth: {
                    username: 'admin',
                    password: 'hackwithme'
                },
                cache: true,
                retries: 3,
                retryTimeout: 3 * 1000
            });

            var db = connection.database(req.body.dataOf);

            //code to show ip along with status code

            if (req.body.check == "all_subdomains") {
                db.get(req.body.check, (err, doc) => {
                    if (err) {
                        console.log(err);
                    }
                    else {
                        res.render('all-subdomains', {
                            data: JSON.parse(doc)
                        });
                    }
                });

            }
            //fetch Github Dorks Data
            else if (req.body.check == 'Github_Dorks_with_org' || req.body.check == 'Github_Dorks_with_Domain') {
                db.get(req.body.check, (err, doc) => {
                    if (err) {
                        console.log(err);
                    }
                    else {
                        res.render('github', {
                            data: JSON.parse(doc)
                        });
                    }
                });
            }
            else if (req.body.delete) {
                db.remove(req.body.check, (err) => {
                    if (err) {
                        console.log(err);
                    }
                    else {
                        res.send("Deleted Successfully!");
                    }
                });
            }
            else {

                db.get(req.body.check, (err, doc) => {
                    if (err) {
                        console.log(err);
                    }
                    else {
                        var x = JSON.parse(doc);
                        var y = Object.values(x)[2];
                        res.render('show-value', {
                            data: y
                        });
                    }
                });
            }
        }
    });

});





//======================= CPU and RAM Usage ========================
app.get('/server-status/', (req, res) => {

    //RAM Usage

    jwt.verify(req.cookies.auth, 'fIskNyRbdGmdaekbMSRlAkU5RIJc6V7I', (err) => {
        if (err) {
            res.status(403).send("You're not authorized to use this framework!");
        }
        else {
            exec('cat /proc/meminfo | grep -i memt | tr -dc "0-9"', (err, total) => {
                if (err) {
                    console.log(err);
                }
                else {
                    exec('cat /proc/meminfo | grep -i mema | tr -dc "0-9"', (err, free) => {
                        if (err) {
                            console.log(err);
                        }
                        else {
                            exec("sar -u 2 2 | grep -i Average |awk '{print substr($0,75,5)}'", (err, used) => {
                                if (err) {
                                    console.log(err);
                                }
                                else {
                                    res.send("Free Memory = " + free / 1024 + " MB" + "\nMemory Usage =" + (100 - ((free / total) * 100)) + " %" + "\nCPU Usage = " + (100 - used) + " %");
                                }
                            });
                        }
                    });
                }
            });
        }
    });

});


//======================= Bypass 403 ========================

app.get('/bypass-403', (req, res) => {
    jwt.verify(req.cookies.auth, 'fIskNyRbdGmdaekbMSRlAkU5RIJc6V7I', (err) => {
        if (err) {
            res.status(403).send("You're not authorized to use this framework!");
        }
        else {
            exec('./tools/byp4xx/byp4xx.sh ' + req.query.url + ' | grep -E "200|301"', (err, stdout) => {
                if (err) {
                    res.send("Error");
                }
                else {
                    res.send(stdout);
                }
            });
        }
    });

});



//======================= Hidden Parameters with Arjun ========================

app.get('/arjun', (req, res) => {

    //if headers/cookies are not included
    jwt.verify(req.cookies.auth, 'fIskNyRbdGmdaekbMSRlAkU5RIJc6V7I', (err) => {
        if (err) {
            res.status(403).send("You're not authorized to use this framework!");
        }
        else {
            if (req.query.url && !req.query.headers) {
                exec('cd ./tools/Arjun/ && python3 arjun.py -u ' + req.query.url, (err, stdout) => {
                    if (err) {
                        console.log(err);
                        res.send("Error");
                    }
                    else {
                        res.send(stdout);
                    }
                });
            }
            //if headers/cookies included in request
            else {
                exec('cd ./tools/Arjun/ && python3 arjun.py -u ' + req.query.url + " --headers '" + req.query.headers + "'", (err, stdout) => {
                    if (err) {
                        console.log(err);
                        res.send("Error");
                    }
                    else {
                        res.send(stdout);
                    }
                });
            }
        }
    });
});


//======================= Javascript Monitor ========================

app.get('/jsmon', (req, res) => {
    jwt.verify(req.cookies.auth, 'fIskNyRbdGmdaekbMSRlAkU5RIJc6V7I', (err) => {
        if (err) {
            res.status(403).send("You're not authorized to use this framework!");
        }
        else {
            if (req.query.url) {
                var data = (req.query.url).split(".js");

                for (x = 0; x < data.length - 1; x++) {
                    fs.appendFileSync('./tools/jsmon/targets/' + req.query.name, data[x] + (".js\n"), { encoding: 'utf-8' });
                }
                res.send("Sucess");
            }
            else {
                exec('ls ./tools/jsmon/targets/', (err, files) => {
                    if (err) {
                        console.log(err);
                    }
                    else {
                        res.send(files);
                    }
                });
            }
        }
    });

});


//======================= Subdomains Monitor with CertEagle ========================

app.get("/certeagle", (req, res) => {
    jwt.verify(req.cookies.auth, 'fIskNyRbdGmdaekbMSRlAkU5RIJc6V7I', (err) => {
        if (err) {
            res.status(403).send("You're not authorized to use this framework!");
        }
        else {
            exec('cat ./tools/CertEagle/domains.yaml', (err, stdout) => {
                if (err) {
                    console.log(err);
                }
                else {
                    res.send(stdout);
                }
            });
        }
    });

});


//======================= Checks Ongoing Scan ========================
app.get("/ongoing-scan", (req, res) => {
    jwt.verify(req.cookies.auth, 'fIskNyRbdGmdaekbMSRlAkU5RIJc6V7I', (err) => {
        if (err) {
            res.status(403).send("You're not authorized to use this framework!");
        }
        else {
            res.send(ongoing_scan);
        }
    });
});



//======================= Log In ========================

var username = 'root';  //change this to update password
var passs = 'toor';

app.get('/login', (req, res) => {
    res.render('login');
});

const limiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 10, message: "Hacker's can't be hacked easily" });


app.post('/login', urlencodedParser, limiter, (req, res) => {
    if (req.body.users == username && req.body.passs == passs) {
        const user = username;
        jwt.sign({ user }, 'fIskNyRbdGmdaekbMSRlAkU5RIJc6V7I', { expiresIn: '3600s' }, (err, token) => {
            res.cookie('auth', token);
            res.redirect('/scan');
        });
    }
    else {
        res.send("Invalid Username or Password!");
    }
});

app.get('/scan', (req, res) => {
    jwt.verify(req.cookies.auth, 'fIskNyRbdGmdaekbMSRlAkU5RIJc6V7I', (err) => {
        if (err) {
            res.status(403).send("You're not authorized to use this framework!");
        }
        else {
            res.render('index');
        }
    });
});


//listen on port 80
app.listen(80, () => {
    console.log("Listening on port 80");
});
