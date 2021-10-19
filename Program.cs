using System;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using Stratumn.CanonicalJson;

static byte[] GetData(JToken obj, string property)
{
    var text = obj[property].ToObject<string>();

    // https://datatracker.ietf.org/doc/html/rfc4648#section-5
    var base64 = text
        .Replace('_', '/')
        .Replace('-', '+');

        return Convert.FromBase64String(base64);
}

static async Task<JObject> ReadJsonInput()
{
    using var input = Console.OpenStandardInput();
    using var text = new StreamReader(input);
    using var reader = new JsonTextReader(text);
    return await JObject.LoadAsync(reader);
}

static byte[] ComputeHash(string text)
{
    var encoding = new UTF8Encoding(encoderShouldEmitUTF8Identifier: false);
    var data = encoding.GetBytes(text);

    // Assume ES256 for now, if need be we can check against the "alg" property.
    using var sha = SHA256.Create();
    return sha.ComputeHash(data);
}

static bool ValidateHash(byte[] certificateData, byte[] hash, byte[] signature)
{
    using var x509 = new X509Certificate2(certificateData);
    var ecdsa = x509.GetECDsaPublicKey();
    return ecdsa.VerifyHash(hash, signature);
}

var root = await ReadJsonInput();

var sig = root["sig"];
var algorithm = sig["alg"].ToObject<string>();
var certificateData = GetData(sig, "cer");
var signature = GetData(sig, "sigvl");

var messageText = root["data"].ToString(Formatting.None);
var canonicalMessage = Canonicalizer.Canonicalize(messageText);

var hash = ComputeHash(canonicalMessage); 
var result = ValidateHash(certificateData, hash, signature);

// TODO: Validate certificate against root CSCA certificate

Console.WriteLine("Result: " + (result ? "SUCCESS" : "FAIL"));
