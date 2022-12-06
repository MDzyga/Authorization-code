using System.Security.Claims;
using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using OpenIddict.Abstractions;
using OpenIddict.Server.AspNetCore;

namespace codeflowSerwer.Controllers
{
    [ApiController]
    [Route("connectz")]
    [RequireHttps]
    public class OldAuthorizationController : ControllerBase
    {
        [HttpPost("token")]
        [Produces("application/json")]
        public async Task<IActionResult> Exchange()
        {
            var request = HttpContext.GetOpenIddictServerRequest() ??
                          throw new InvalidOperationException("The OpenID Connect request cannot be retrieved.");

            ClaimsPrincipal claimsPrincipal;

            if (request.IsClientCredentialsGrantType())
            {
                // Note: the client credentials are automatically validated by OpenIddict:
                // if client_id or client_secret are invalid, this action won't be invoked.

                var identity = new ClaimsIdentity(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);

                // Subject (sub) is a required field, we use the client id as the subject identifier here.
                identity.AddClaim(OpenIddictConstants.Claims.Subject, request.ClientId ?? throw new InvalidOperationException());

                // Add some claim, don't forget to add destination otherwise it won't be added to the access token.
                identity.AddClaim("some-claim", "some-value", OpenIddictConstants.Destinations.AccessToken);

                claimsPrincipal = new ClaimsPrincipal(identity);

                claimsPrincipal.SetScopes(request.GetScopes());
            }
            else if (request.IsAuthorizationCodeGrantType())
            {
                // Retrieve the claims principal stored in the authorization code
                claimsPrincipal = (await HttpContext.AuthenticateAsync(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme)).Principal;
            }
            else
            {
                throw new InvalidOperationException("The specified grant type is not supported.");
            }

            return SignIn(claimsPrincipal, OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
        }

        [HttpGet("authorize")]
        [HttpPost("authorize")]
        [IgnoreAntiforgeryToken]
        public async Task<IActionResult> Authorize()
        {
            var request = HttpContext.GetOpenIddictServerRequest() ??
                          throw new InvalidOperationException("The OpenID Connect request cannot be retrieved.");

            // Retrieve the Windows identity associated with the current authorization request.
            // If it can't be extracted, trigger an Integrated Windows Authentication dance.
            var result = await HttpContext.AuthenticateAsync(CookieAuthenticationDefaults.AuthenticationScheme);
            if (result is not { Succeeded: true })
            {
                return Challenge(
                    authenticationSchemes : CookieAuthenticationDefaults.AuthenticationScheme,
                    properties : new AuthenticationProperties
                    {
                        RedirectUri = Request.PathBase + Request.Path + QueryString.Create(
                            Request.HasFormContentType ? Request.Form.ToList() : Request.Query.ToList())
                    });
            }

            // Retrieve the application details from the database.
            //  var application = await HttpContext.AuthenticateAsync(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);

            // This sample doesn't include a consent view mechanism and requires that the application use implicit consents.
            //if (!await _applicationManager.HasConsentTypeAsync(application, OpenIddictConstants.ConsentTypes.Implicit))
            //{
            //    return Forbid(
            //        authenticationSchemes: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
            //        properties: new AuthenticationProperties(new Dictionary<string, string>
            //        {
            //            [OpenIddictServerAspNetCoreConstants.Properties.Error] = OpenIddictConstants.Errors.ServerError,
            //            [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] =
            //                "The specified client application is not correctly configured."
            //        }));
            //}

            // Create the claims-based identity that will be used by OpenIddict to generate tokens.
            var identity = new ClaimsIdentity(result.Principal.Claims,
                authenticationType : TokenValidationParameters.DefaultAuthenticationType,
                nameType : OpenIddictConstants.Claims.Name,
                roleType : OpenIddictConstants.Claims.Role);

            // The Windows identity doesn't contain the "sub" claim required by OpenIddict to represent
            // a stable identifier of the authenticated user. To work around that, a "sub" claim is
            // manually created by using the primary SID claim resolved from the Windows identity.
            var sid = identity.FindFirst(ClaimTypes.PrimarySid)?.Value;
            identity.AddClaim(new Claim(OpenIddictConstants.Claims.Subject, sid));

            // Allow all the claims resolved from the principal to be copied to the access and identity tokens.
            foreach (var claim in identity.Claims)
            {
                claim.SetDestinations(OpenIddictConstants.Destinations.AccessToken, OpenIddictConstants.Destinations.IdentityToken);
            }

            return SignIn(new ClaimsPrincipal(identity), OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
        }

        //[Authorize]
        //[FormValueRequired("submit.Accept")]
        //[HttpPost("~/connect/authorize")]
        //[ValidateAntiForgeryToken]
        //public async Task<IActionResult> Accept()
        //{
        //    var request = HttpContext.GetOpenIddictServerRequest() ??
        //                  throw new InvalidOperationException("The OpenID Connect request cannot be retrieved.");

        //    // Returning a SignInResult will ask OpenIddict to issue the appropriate access/identity tokens.
        //    return SignIn(new ClaimsPrincipal(), OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
        //}
    }
}