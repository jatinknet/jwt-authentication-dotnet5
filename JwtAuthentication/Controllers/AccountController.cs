using JwtAuthentication.Models;
using JwtAuthentication.Services;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using System.Threading.Tasks;

namespace JwtAuthentication.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AccountController : ControllerBase
    {
        private readonly IJwtService _jwtService;

        [HttpPost("[action]")]
        public async Task<IActionResult> AuthToken(AuthRequest authRequest)
        {
            var token=await _jwtService.GetTokenAsync(authRequest);
            if (token == null)
                return Unauthorized();

            return Ok(new AuthResponse { Token=token});

        }

        public AccountController(IJwtService jwtService)
        {
            _jwtService = jwtService;
        }
    }
}
