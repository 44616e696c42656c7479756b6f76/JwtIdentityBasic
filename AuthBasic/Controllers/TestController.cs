using AuthBasic.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace AuthBasic.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    [Authorize(Roles = "User")]
    public class TestController : ControllerBase
    {
        [HttpGet]
        [Route("userdata")]
        public async Task<IActionResult> GetDataUser()
        {
            return Ok(new Response { Status = "Success", Message = "User data." });
        }


        [HttpGet]
        [Authorize(Roles = "Admin, Moderator")]
        [Route("admindata")]
        public async Task<IActionResult> GetDataAdmin()
        {
            return Ok(new Response { Status = "Success", Message = "Admin data." });
        }
    }
}
