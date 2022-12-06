using Microsoft.AspNetCore.Mvc;

namespace webApp.Controllers
{
    public class CallbackController : Controller
    {
        public IActionResult Index()
        {
            var authCode = Request.QueryString;
            var req = HttpContext.Request;
            var res = HttpContext.Response;
            return Redirect("/");
        }
    }
}