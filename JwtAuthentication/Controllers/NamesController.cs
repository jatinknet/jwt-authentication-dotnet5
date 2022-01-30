using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace JwtAuthentication.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class NamesController : ControllerBase
    {
        [Authorize]
        [HttpGet("[action]")]
        public async Task<IActionResult> GetNames()
        {
            var names= await Task.FromResult(new List<string> { "Adam", "Robert","John"});
            return Ok(names);
        }
    }
}
