using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.AspNetCore.Mvc;
using System.Threading.Tasks;

namespace BackendForFrontend.Controllers
{
    [ApiController]
    [Route("")]
    public class DefaultController : ControllerBase
    {
        [HttpGet]
        public IActionResult Default()
        {
            return Ok("ok");
        }
    }
}
