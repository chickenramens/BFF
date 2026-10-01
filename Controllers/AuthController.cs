using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;

namespace BackendForFrontend.Controllers
{
    public class AuthController : Controller
    {

        public ActionResult Login(string returnUrl = "/")
        {
            //return new ChallengeResult("Auth0", new AuthenticationProperties() { RedirectUri = returnUrl });
            return new ChallengeResult("OpenIdConnect", new AuthenticationProperties() { RedirectUri = returnUrl });
        }

        [Authorize]
        public async Task<ActionResult> Logout()
        {
          HttpContext.Session.Clear();
          await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);

          return new SignOutResult("OpenIdConnect", new AuthenticationProperties
          {
            RedirectUri = "/"
          });
        }


        public ActionResult GetUser()
        {
            if (User.Identity.IsAuthenticated)
            {
                var claims = ((ClaimsIdentity)this.User.Identity).Claims.Select(c =>
                    new { type = c.Type, value = c.Value })
                    .ToArray();

                return Json(new { isAuthenticated = true, claims = claims });
            }

            return Json(new { isAuthenticated = false });
        }

        [Authorize]
        public ActionResult GetTest()
        {
            return Json(new { isAuthenticated = true, message = "Hello from the API" });
        }
    }


}
