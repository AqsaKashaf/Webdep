



const myArgs = process.argv.slice(2);
const sslCertificate = require('get-ssl-certificate')

website = myArgs[0]
get_certificate(website)

function get_certificate(website) {        
    try {
        sslCertificate.get(website,3000, 443,"https:",true).then(function (certificate) {
            let result = {}
            result["CA"] = certificate.issuer.O
            result["ocsp"] = certificate.infoAccess["OCSP - URI"]
            let san = certificate.subjectaltname.replaceAll(",",";").replaceAll(" ","").replaceAll("DNS:","")
            result["san"] = san.split(";")
            console.log(JSON.stringify(result))
        });
    } catch(e) {
        return e
    }              
}
      
           
      
            
    // data.forEach(line =>  {
    // //     console.log(x++);
    //     website = line.split(",")[1]
    //     try {
    //         sslCertificate.get(website).then(function (certificate) {
    //             try {
    //                 let data = JSON.stringify(certificate,null, 4);
    //                 fs.appendFileSync('outputs/ca',data + "\n");
    //                 // file written successfully
    //               } catch (err) {
    //                 fs.appendFileSync('outputs/ca',line + "," + err.message + "\n");
    //               }
    //         });
    //         await new Promise(resolve => setTimeout(resolve, 1000));
    //     } catch(err) {
    //         fs.appendFileSync('outputs/ca',line + "," + err.message + "\n");
    //     }
    // });




