# Utilities

These utilities are primarily for [Generic Character Sheet](https://github.com/Rangoric/generic-character-sheet-website).

## JWT

Wrap up functionality to deal with jwt tokens generated by Auth0. Designed to work with AWS Lambda Functions and Azure Functions.

### How To Use

#### Configuration

Environment Variables to set:

- `Authorization-Configuration-Url` : `https://[Domain in Auth0]/.well-known/openid-configuration`
- `Authorization-ClientID` : `[Your ClientID]`
- `Authorization-Issuer` : `https://[Domain in Auth0]/`
- `Authorization-Metadata` : `https://[Your application website]/app_metadata`

`[Domain in Auth0]` can be gotten by going to Applications -> Settings, it will be a readonly setting near the top.
`[Your application website]` This requires a rule set up to copy data to the token using the namespace you decide on.

```fsharp
open Utilities.Jwt

let (isValid, claimPrinciple, actorProfile) = JwtSecurity.IsValid request//(request:HttpRequest)
let (isValid, claimPrinciple, actorProfile) = JwtSecurity.IsValidInGroups request groupList//(request:HttpRequest) (groupList:string list)
```

I don't rememeber if F# and C# tuples are compatible so this might work.

```csharp
using Utilities.Jwt;

var (isValid, claimPrinciple, actorProfile) = JwtSecurity.IsValid(request);
var (isValid, claimPrinciple, actorProfile) = JwtSecurity.IsValidInGroups(request, groupList);
```

### Testing

To Be Improved. Have to change it to expose testable pieces. Or expose itself in a testable way.
