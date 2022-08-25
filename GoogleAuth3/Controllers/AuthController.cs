using AspNet.Security.OAuth.GitHub;
using GoogleAuth3.Models;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.Google;
using Microsoft.AspNetCore.Authentication.MicrosoftAccount;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Linq;
using System.Security.Claims;

namespace GoogleAuth3.Controllers
{
    public class AuthController : Controller
    {
        [HttpGet]
        public IActionResult LogIn()
        {
            if (HttpContext.User.Identity.IsAuthenticated)
                return RedirectToAction("Profile", "Auth");
            return View();
        }

        [HttpGet]
        public IActionResult AuthLogin(AuthType type)
        {
            AuthenticationProperties properties = new() { RedirectUri = Url.Action("AuthResponse") };
            string scheme;
            switch (type)
            {
                case AuthType.GoogleAuth:
                    scheme = GoogleDefaults.AuthenticationScheme;
                    break;
                case AuthType.MicrosoftAuth:
                    scheme = MicrosoftAccountDefaults.AuthenticationScheme;
                    break;
                case AuthType.GithubAuth:
                    scheme = GitHubAuthenticationDefaults.AuthenticationScheme;
                    break;
                default:
                    return Redirect(nameof(LogIn));
            }
            return Challenge(properties, scheme);
        }

        [HttpGet]
        public async Task<IActionResult> AuthResponse()
        {
            var claims = HttpContext.User.Identities.FirstOrDefault()
                .Claims.Select(c => new{
                    c.Issuer,
                    c.OriginalIssuer,
                    c.Type,
                    c.Value
                });
            return await Auth(claims.Where(c => c.Type.EndsWith("/name")).FirstOrDefault()?.Value ?? String.Empty,
                claims.Where(c => c.Type.EndsWith("/emailaddress")).FirstOrDefault()?.Value ?? String.Empty);
        }

        [HttpGet]
        public IActionResult Profile()
        {
            var claims = HttpContext.User.Claims.Select(claim => new
            {
                claim.Issuer,
                claim.OriginalIssuer,
                claim.Type,
                claim.Value
            });
            UserViewModel user = new UserViewModel()
            {
                Username = claims.ElementAtOrDefault(0)?.Value,
                Email = claims.ElementAtOrDefault(1)?.Value,
                Role = claims.ElementAtOrDefault(2)?.Value
            };
            return View(user);
        }

        [Authorize()]
        [HttpGet]
        public async Task<IActionResult> LogOut()
        {
            return await Exit();
        }

        private async Task<IActionResult> Auth(string name, string email)
        {
            List<Claim> claims = new()
            {
                new Claim(ClaimsIdentity.DefaultNameClaimType, name),
                new Claim("Email", email),
                new Claim(ClaimsIdentity.DefaultRoleClaimType, "Admin")
            };

            ClaimsIdentity claimsIdentity = new ClaimsIdentity(claims,
                "AuthAppCookie",
                ClaimsIdentity.DefaultNameClaimType,
                ClaimsIdentity.DefaultRoleClaimType);

            await HttpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme,
                new ClaimsPrincipal(claimsIdentity));

            return RedirectToAction("Profile", "Auth");
        }

        private async Task<IActionResult> Exit()
        {
            await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
            return RedirectToAction("LogIn");
        }
    }
}
