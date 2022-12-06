using System.Security.Claims;
using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Primitives;
using OpenIddict.Abstractions;
using OpenIddict.Server.AspNetCore;

namespace codeflowSerwer.Controllers
{
    [ApiController]
    [Route("connect")]
    [RequireHttps]
    public class AuthorizationController : Controller
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
            var request = HttpContext.GetOpenIddictServerRequest();
            if (request.HasPrompt(OpenIddictConstants.Prompts.Login))
            {
                var prompt = string.Join(" ", request.Prompt);
                var parameters = Request.HasFormContentType
                    ? Request.Form.Where(parameter => parameter.Key != OpenIddictConstants.Parameters.Prompt).ToList()
                    : Request.Query.Where(parameter => parameter.Key != OpenIddictConstants.Parameters.Prompt).ToList();
                parameters.Add(KeyValuePair.Create(OpenIddictConstants.Parameters.Prompt, new StringValues(prompt)));
                return Challenge(
                    authenticationSchemes : IdentityConstants.ApplicationScheme,
                    properties : new AuthenticationProperties
                    {
                        RedirectUri = Request.PathBase + Request.Path + QueryString.Create(parameters)
                    });
            }

            var result = await HttpContext.AuthenticateAsync(CookieAuthenticationDefaults.AuthenticationScheme);
            if (!result.Succeeded || (request.MaxAge != null && result.Properties?.IssuedUtc != null &&
                                      DateTimeOffset.UtcNow - result.Properties.IssuedUtc > TimeSpan.FromSeconds(request.MaxAge.Value)))
            {
                if (request.HasPrompt(OpenIddictConstants.Prompts.None))
                {
                    return Forbid(
                        authenticationSchemes : CookieAuthenticationDefaults.AuthenticationScheme,
                        properties : new AuthenticationProperties(new Dictionary<string, string>
                        {
                            [OpenIddictServerAspNetCoreConstants.Properties.Error] = OpenIddictConstants.Errors.LoginRequired,
                            [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] = "The user is not logged in."
                        }!));
                }

                return Challenge(
                    authenticationSchemes : CookieAuthenticationDefaults.AuthenticationScheme,
                    properties : new AuthenticationProperties
                    {
                        RedirectUri = Request.PathBase + Request.Path + QueryString.Create(
                            Request.HasFormContentType ? Request.Form.ToList() : Request.Query.ToList())
                    });
            }

            //var user = await _userManager.GetUserAsync(result.Principal) ??
            //           throw new InvalidOperationException("The user details cannot be retrieved.");

            //var application = await _applicationManager.FindByClientIdAsync(request.ClientId!) ??
            //                  throw new InvalidOperationException("Details concerning the calling client application cannot be found.");

            //var authorizations = await _authorizationManager.FindAsync(
            //    subject: await _userManager.GetUserIdAsync(user),
            //    client: (await _applicationManager.GetIdAsync(application))!,
            //    status: OpenIddictConstants.Statuses.Valid,
            //    type: OpenIddictConstants.AuthorizationTypes.Permanent,
            //    scopes: request.GetScopes()).ToListAsync();

            //switch (await _applicationManager.GetConsentTypeAsync(application))
            //{
            //    case OpenIddictConstants.ConsentTypes.External when !authorizations.Any():
            //        return Forbid(
            //            authenticationSchemes: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
            //            properties: new AuthenticationProperties(new Dictionary<string, string>
            //            {
            //                [OpenIddictServerAspNetCoreConstants.Properties.Error] = Errors.ConsentRequired,
            //                [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] =
            //                    "The logged in user is not allowed to access this client application."
            //            }!));

            //    case OpenIddictConstants.ConsentTypes.Implicit:
            //    case OpenIddictConstants.ConsentTypes.External when authorizations.Any():
            //    case OpenIddictConstants.ConsentTypes.Explicit when authorizations.Any() && !request.HasPrompt(Prompts.Consent):
            //        var principal = await _signInManager.CreateUserPrincipalAsync(user);
            //        principal.SetScopes(request.GetScopes());
            //        principal.SetResources(await _scopeManager.ListResourcesAsync(principal.GetScopes()).ToListAsync());

            //        var authorization = authorizations.LastOrDefault();
            //        if (authorization == null)
            //        {
            //            authorization = await _authorizationManager.CreateAsync(
            //                principal: principal,
            //                subject: await _userManager.GetUserIdAsync(user),
            //                client: (await _applicationManager.GetIdAsync(application))!,
            //                type: OpenIddictConstants.AuthorizationTypes.Permanent,
            //                scopes: principal.GetScopes());
            //        }

            //        principal.SetAuthorizationId(await _authorizationManager.GetIdAsync(authorization));

            //        foreach (var claim in principal.Claims)
            //        {
            //            claim.SetDestinations(GetDestinations(claim, principal));
            //        }

            //        return SignIn(principal, OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);

            //    default:
            //        return View(new AuthorizeViewModel
            //        {
            //            ApplicationName = "Andrzej",//await _applicationManager.GetDisplayNameAsync(application),
            //            Scope = request.Scope
            //        });
            //}

            return View(new AuthorizeViewModel
            {
                ApplicationName = "Andrzej", //await _applicationManager.GetDisplayNameAsync(application),
                Scope = request.Scope
            });
        }

        [FormValueRequired("submit.Accept")]
        [HttpPost("authorize")]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Accept()
        {
            var request = HttpContext.GetOpenIddictServerRequest() ??
                          throw new InvalidOperationException("The OpenID Connect request cannot be retrieved.");

            // Returning a SignInResult will ask OpenIddict to issue the appropriate access/identity tokens.
            return SignIn(new ClaimsPrincipal(), OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
        }
    }
}