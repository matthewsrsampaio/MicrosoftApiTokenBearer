using Microsoft.AspNetCore.Authentication.BearerToken;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;

namespace ApiTokenBearer.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        [HttpGet("/login")]
        public IActionResult Login(string username, string password)
        {
            if (IsvalidUser(username, password))
                {
                    var claimsPrincipal = new ClaimsPrincipal(
                    new ClaimsIdentity(
                        new[] { new Claim(ClaimTypes.Name, username) },
                        BearerTokenDefaults.AuthenticationScheme
                        )
                    );
                    return SignIn(claimsPrincipal);
                }
            return Unauthorized("Credenciais inválidas");
        }

        private bool IsvalidUser(string username, string password)
        {
            return username == "Matthews" && password == "123456";
        }

        [HttpGet("/user")]
        [Authorize]
        public IActionResult GetUser()
        {
            var user = User;
            if(user?.Identity?.IsAuthenticated ?? false)
            {
                return Ok($"Bem-vindo {user.Identity.Name}!");
            }
            return Unauthorized();
        }
    }
}
