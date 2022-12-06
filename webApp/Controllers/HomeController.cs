using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using System.Web;
using Microsoft.AspNetCore.Mvc;
using webApp.Models;

namespace webApp.Controllers
{
    public class HomeController : Controller
    {
        private readonly ILogger<HomeController> _logger;

        public HomeController(ILogger<HomeController> logger)
        {
            _logger = logger;
        }

        [Consumes("application/json")]
        public async Task<IActionResult> Index()
        {
            var parameters = new List<KeyValuePair<string, string>>
            {
                new KeyValuePair<string, string>("client_id", "postman"),
                new KeyValuePair<string, string>("client_secret", "postman-secret"),
                new KeyValuePair<string, string>("grant_type", "authorization_code"),
                new KeyValuePair<string, string>("redirect_uri", "https://localhost:7276/callback"),
                new KeyValuePair<string, string>("response_type", "code"),
                new KeyValuePair<string, string>("response_mode", "query"),
                new KeyValuePair<string, string>("code_challenge", GenerateCodeChallenge()),
                new KeyValuePair<string, string>("code_challenge_method", "S256")
            };
            string url = "localhost:7092";
            var content = new FormUrlEncodedContent(parameters);
            var client = new HttpClient();

            var builder = new UriBuilder($"https://{url}/connect/authorize");
            var query = HttpUtility.ParseQueryString(builder.Query);
            foreach (var item in parameters)
            {
                query[item.Key] = item.Value;
            }

            builder.Query = query.ToString();

            string urlWithQuery = builder.ToString();

            //   var smthg = await client.GetAsync(urlWithQuery);
            var smthg2 = await client.PostAsync(url, content);
            return RedirectPermanent(smthg2.RequestMessage.RequestUri.ToString());
        }

        private string GenerateCodeChallenge()
        {
            string chars = "abcdefghijklmnopqrstuvwxyz123456789";
            var nonce = new char[100];
            var random = new Random();
            for (int i = 0; i < nonce.Length; i++)
            {
                nonce[i] = chars[random.Next(chars.Length)];
            }

            string codeVerifier = new string(nonce);
            using var sha256 = SHA256.Create();
            var hash = sha256.ComputeHash(Encoding.UTF8.GetBytes(codeVerifier));
            return Convert.ToBase64String(hash).Replace("+/", "-_").Replace("=", "");
        }

        public IActionResult Privacy()
        {
            return View();
        }

        [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
        public IActionResult Error()
        {
            return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
        }
    }
}