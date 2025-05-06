using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace MSIT64Api.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class MemberController : ControllerBase
    {
        public ActionResult Login(string name, string password)
        {
            //登入成功
            //產生JWT
            return Ok();
        }
    }
}
