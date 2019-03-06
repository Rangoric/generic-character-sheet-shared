namespace Utilities.Jwt

open Microsoft.IdentityModel.Protocols
open Microsoft.IdentityModel.Protocols
open Microsoft.IdentityModel.Protocols.OpenIdConnect
open System.Net.Http.Headers
open Microsoft.IdentityModel.Tokens
open System.Threading
open System.Threading.Tasks
open System.IdentityModel.Tokens.Jwt
open Microsoft.IdentityModel.Tokens
open System
open Microsoft.AspNetCore.Http
open System.Linq
open System.Net.Http
open System.Net.Http
open System.Net.Http.Headers
open Microsoft.IdentityModel.Tokens
open System.Security.Claims

module JWTSecurity =
    let Setup configurationUrl audience issuer =
        let configuration =
            let documentRetriever = HttpDocumentRetriever();
            documentRetriever.RequireHttps <- true
            new ConfigurationManager<OpenIdConnectConfiguration>(
                configurationUrl,
                OpenIdConnectConfigurationRetriever(),
                documentRetriever)
        let validationParameter =
            let result = TokenValidationParameters()
            result.RequireSignedTokens <- true
            result.ValidAudience <- audience
            result.ValidateAudience <- true
            result.ValidIssuer <- issuer
            result.ValidateIssuer <- true
            result.ValidateIssuerSigningKey <- true
            result.ValidateLifetime <- true
            result.IssuerSigningKeys <- 
                (configuration.GetConfigurationAsync(CancellationToken.None)
                |> Async.AwaitTask
                |> Async.RunSynchronously).SigningKeys
            result       
        let getHeaderValue (request:HttpRequest) =
            let headerValue =
                match request.Headers.ContainsKey "Authorization" with
                | true ->
                    request.Headers.["Authorization"]
                | false ->
                    match request.Headers.ContainsKey "authorization" with
                    | true ->
                        request.Headers.["authorization"]
                    | false ->
                        raise (HttpRequestException "No Token")
            let splitHeader = headerValue.ToString().Split ' '
            AuthenticationHeaderValue(splitHeader.[0], splitHeader.[1])
        let rec authorize (request:HttpRequest) = 
            let header = getHeaderValue request
            match header with
            | null -> None
            | _ ->
                match header.Scheme with
                | "Bearer" ->
                    let handler = JwtSecurityTokenHandler()
                    //try
                    Some (handler.ValidateToken(header.Parameter, validationParameter))
                    //with
                        // | :? SecurityTokenSignatureKeyNotFoundException ->
                        //     configuration.RequestRefresh()
                        //     authorize request
                        // | _ -> None
                | _ -> None
        authorize
    let SetupWithEnvironmentVariable:(HttpRequest -> Option<(ClaimsPrincipal * SecurityToken)>) =
        Setup
            (Environment.GetEnvironmentVariable "Authorization-Configuration-Url")
            (Environment.GetEnvironmentVariable "Authorization-ClientID")
            (Environment.GetEnvironmentVariable "Authorization-Issuer")
    let GetClaim request =
        let optionTuple = SetupWithEnvironmentVariable request
        match optionTuple with
        | Some (claim, _) ->
            claim
        | None ->
            null
    let GetUserId (claimsPrincipal:ClaimsPrincipal) =
        let identity = claimsPrincipal.Identity :?> ClaimsIdentity
        let claims = identity.Claims.ToArray()
        let subjectClaim =
            claims 
            |> Array.filter (fun t -> t.Type = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier")
            |> Array.head
        let userID = subjectClaim.Value
        userID
        
    let IsValid request =
        let optionTuple = SetupWithEnvironmentVariable request
        match optionTuple with
        | Some (_) ->
            true
        | None ->
            false