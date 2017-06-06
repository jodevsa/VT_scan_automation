 'use strict'
 const crypto = require('crypto')
 const request = require('request').defaults({jar: true})
 const promise = require('bluebird')
 const cheerio = require('cheerio')
 const fs = require('fs')
 const path = require('path')
 const colors = require('colors')
 const Table = require('cli-table')
 const events = require('events')
 const stream = require('stream')
 function options () {
   const options = {
     gzip: true,
     followRedirect: false,
     headers: {
       'User-Agent': 'Mozilla/5.0 (X11; Fedora; Linux x86_64; rv:48.0) Gecko/20100101 Firefox/48.0',
       'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
     }
   }
   return options
 }
 function assemble_stream_and_cal_hash (stream, func) {
   let data = ''
   let shasum = crypto.createHash('sha256')
   stream.on('data', function (chunck) {
     console.log(data)
     data += chunck
     shasum.update(chunck)
   })
   stream.on('end', function () {
     return func({data: data, hash: shasum.digest('hex')})
   })
 }
 function CreateStreamFromStr (str) {
   let _stream = new stream.Readable()
   _stream._read = function noop () {}
   _stream.push(str)
   _stream.push(null)
   return _stream
 }

 function parseBody (body) {
   let parsed_result = []
   let $ = cheerio.load(body)
   $('table tr').map(function (n, el) {
     if (n !== 0) {
       let antivirus, result, update = ''
       $(el).children('td').map(function (noon, element) {
         if (noon === 0) {
           antivirus = $(element).text().trim()
         }
         if (noon === 2) {
           update = $(element).text().trim()
         }

         if (noon === 1) {
           if ($(element).hasClass('text-green')) {
             result = 'clean'
           } else {
             if ($(element).hasClass('text-gray')) {
               result = 'not supported'
             } else {
               if ($(element).hasClass('text-red')) {
                 result = $(element).text().trim()
               }
             }
           }
         }
       })
       parsed_result.push({antivirus: antivirus, result: result, update: update})
     }
   })
   return parsed_result
 }

 function GetUselessCookies () {
   return new Promise(function (resolve, reject) {
     let http_options = options()
     http_options.url = 'https://virustotal.com/en'
     http_options.method = 'GET'
     request(http_options, function (err, res, body) {
       if (err) {
         return reject(err)
       }
       return resolve('DONE')
     })
   })
 }

 function upload (exist_result, data, filename, hash, emitter) {
   return new Promise(function (resolve, reject) {
     let http_options = options()
     http_options.url = exist_result.json.upload_url
     let formData = {
       file: {
         value: data,
         options: {
           filename: filename,
           contentType: 'text/plain'
         }
       },
       ajax: 'true',
       remote_addr: '8.8.8.8',
       sha256: hash,
       last_modified: '2017-01-05T06:06:14.000Z'

     }
     http_options.formData = formData
     http_options.method = 'POST'
     request(http_options, function (err, res, body) {
       if (err) {
         return reject(err)
       }
       if (res.statusCode !== 302) {
         return reject(new Error('something is wrong after uploading'))
       }
       let location = res.headers.location
       let last_status = ''
       http_options = options()
       http_options.url = location
       http_options.method = 'GET'
       let result_watcher = setInterval(function () {
         http_options.url = location + '?last-status=' + last_status + '&_=' + (new Date().getTime()).toString()
         console.log(http_options.url.toString().blue)
         request(http_options, function (err, res, body) {
           if (err) {
             clearInterval(result_watcher)
             console.log('err 70 index.js', err)
             return reject(err)
           }
           try {
             let obj = JSON.parse(body)

             last_status = obj.status
             console.log(last_status.toString().yellow)
             if (last_status == 'completed') {
               console.log(obj.analysis_url)
               clearInterval(result_watcher)
               console.log('cleared result watcher.')
               let url = 'https://virustotal.com/' + obj.analysis_url
               return resolve(obj.results)
              // return resolve('https://virustotal.com/'+obj.analysis_url);
             } else {
               if (obj.results != null && obj.results != undefined) {
                 emitter.emit('result', parseBody(obj.results))
               }
             }
           } catch (e) {
             fs.writeFileSync('body.txt', body)
           }
         })
       }, 10000)
     })
   })
 }
 function controller (filename, data, hash, emitter) {
   return function (exist_result) {
     return new Promise(function (resolve, reject) {
       if (exist_result.found) {
         let http_options = options()
         http_options.url = 'https://virustotal.com/en/file/' + hash + '/analysis/' + (new Date().getTime()).toString() + '/info?last-status=analysing&_' + (new Date().getTime()).toString() + '/?last-status'
         console.log(http_options.url)
         http_options.method = 'GET'
         http_options.followRedirect = true
         request(http_options, function (err, res, body) {
           if (err) {
             console.log('err', err)
             return reject(err)
           }
           try {
             let obj = JSON.parse(body)

             let parsed_result = (parseBody(obj.results))

             return resolve(parsed_result)
           } catch (e) {
             fs.writeFileSync('body.txt', body)
           }
         })
       } else {
         upload(exist_result, data, filename, hash, emitter)
  .then(function (data) { return resolve(parseBody(data)) })
       }
     })
   }
 }
 function CheckIfFileExists (hash) {
   return function (message) {
     return new Promise(function (resolve, reject) {
       let http_options = options()
       let timestamp = new Date().getTime()
       http_options.url = 'https://virustotal.com/en/file/upload/?sha256=' + hash + '&_=' + timestamp
       http_options.method = 'GET'
       request(http_options, function (err, res, body) {
         if (err) {
           return reject(err)
         }
         try {
           let json_object = JSON.parse(body)
           return resolve({found: json_object.file_exists, json: json_object})
         } catch (e) {
           fs.writeFileSync('body.txt', body)
         }
       })
     })
   }
 }

 function ParseResult () {
   return function (result) {
     return new Promise(function (resolve, reject) {
       let parsed_result = []
       let http_options = options()
       http_options.url = 'https://virustotal.com/' + result
       http_options.method = 'GET'
       request(http_options, function (err, res, body) {
         if (err) {
           console.log(err)
           return reject(err)
         }
         let $ = cheerio.load(body)
         console.log(res)
         console.log('Cheerio')
         $('#results table tr').map(function (n, el) {
           if (n != 0) {
             let antivirus, result, update = ''
             $(el).children('td').map(function (noon, element) {
               if (noon == 0) {
                 antivirus = $(element).text().trim()
               }
               if (noon == 2) {
                 update = $(element).text().trim()
               }

               if (noon == 1) {
                 if ($(element).hasClass('text-green')) {
                   result = 'clean'
                 } else {
                   if ($(element).hasClass('text-gray')) {
                    result = 'not supported'
                  } else {
                    if ($(element).hasClass('text-red')) {
                      result = $(element).text().trim()
                    }
                  }
                 }
               }
             })
             parsed_result.push({antivirus: antivirus, result: result, update: update})
             console.log('herepu')
             console.log(antivirus, result, update)
           }
         })
         return resolve(parsed_result)
       })
     })
   }
 }
 function PrintResults (func) {
   return function (results) {
     var table = new Table({
       head: ['Antivirus', 'Result', 'Update'],
       colWidths: [20, 50, 10]
     })

     results.map(function (el) {
       if (el.result == 'clean') {
         table.push([el.antivirus, el.result.bgGreen, el.update])
       } else {
         table.push([el.antivirus, el.result.bgRed, el.update])
       }
     })

     return func(table.toString())
   }
 };

 function AV_SCAN (filename, stream, func) {
   let emitter = new events.EventEmitter()
   assemble_stream_and_cal_hash(stream, function (result) {
     let hash = result.hash
     let data = result.data
     console.log('hash:', hash.toString().red)
     GetUselessCookies()
      .then(CheckIfFileExists(hash))
      .then(controller(filename, data, hash, emitter))
      .then(PrintResults(func))
      .catch(function (err) { console.log(err) })
   })
   return emitter
 }
 console.time('exit')
 process.on('SIGINT', (code) => {
   console.log('time taken'.red)
   console.timeEnd('exit')
   process.exit()
 })
 process.on('exit', (code) => {
   console.log('time taken'.red)
   console.timeEnd('exit')
 })
 if (process.argv.length == 2) {
   let count = 0
   let filename = 'testing'

  // random data...

   setInterval(function () {
     let data = Math.random().toString() + ' ' + Math.random().toString() + ' ' + Math.random().toString() + ' ' + Math.random().toString() + ' '
     let stream = CreateStreamFromStr(data)
     AV_SCAN(filename, stream, function (results) {
       console.log(results)
       console.log(('COUNT: ' + count.toString()).bgRed)
       count += 1
     })
   }, 800)
 } else {
   if (process.argv.length == 3) {
     let file_path = process.argv[2]
     let stream = fs.createReadStream(file_path)
     let filename = path.basename(file_path)
     console.log('file name:', file_path.toString().green)
     AV_SCAN(filename, stream, function (results) {
       console.log(results)
     }).on('result', function (results) {
       PrintResults(function (data) {
         console.log(data)
       })(results)
     })
   }
 }
