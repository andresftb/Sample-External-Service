// From DataWire Example service as base

package main

// NOTE: VERY WIP, DOES NOT WORK YET

import (
	"context"
	"log"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"time"

	"github.com/golang/protobuf/ptypes/wrappers"
	"google.golang.org/genproto/googleapis/rpc/code"
	"google.golang.org/genproto/googleapis/rpc/status"
	"google.golang.org/grpc"

	envoyCoreV3 "github.com/datawire/ambassador/v2/pkg/api/envoy/config/core/v3"
	envoyAuthV3 "github.com/datawire/ambassador/v2/pkg/api/envoy/service/auth/v3"
	envoyType "github.com/datawire/ambassador/v2/pkg/api/envoy/type/v3"

	"github.com/datawire/dlib/dhttp"

	firebase "firebase.google.com/go/v4"
	"firebase.google.com/go/v4/auth"
)

func main() {

	grpcHandler := grpc.NewServer()
	envoyAuthV3.RegisterAuthorizationServer(grpcHandler, &AuthService{})

	sc := &dhttp.ServerConfig{
		Handler: grpcHandler,
	}

	log.Print("starting...")
	log.Fatal(sc.ListenAndServe(context.Background(), ":3000"))
}

type AuthService struct{}

func (s *AuthService) Check(ctx context.Context, req *envoyAuthV3.CheckRequest) (*envoyAuthV3.CheckResponse, error) {
	log.Println("ACCESS",
		req.GetAttributes().GetRequest().GetHttp().GetMethod(),
		req.GetAttributes().GetRequest().GetHttp().GetHost(),
		req.GetAttributes().GetRequest().GetHttp().GetBody(),
	)
	log.Println("~~~~~~~~> REQUEST BODY ~~~~~~~~>", req.GetAttributes().GetRequest().GetHttp().GetBody())
	log.Println("~~~~~~~~> REQUEST RAW BODY ~~~~~~~~>", req.GetAttributes().GetRequest().GetHttp().GetRawBody())
	log.Println("~~~~~~~~> REQUEST HTTP ~~~~~~~~>", req.GetAttributes().GetRequest().GetHttp())
	log.Println("~~~~~~~~> REQUEST ~~~~~~~~>", req.GetAttributes().GetRequest())
	requestURI, err := url.ParseRequestURI(req.GetAttributes().GetRequest().GetHttp().GetPath())
	if err != nil {
		log.Println("=> ERROR", err)
		return &envoyAuthV3.CheckResponse{
			Status: &status.Status{Code: int32(code.Code_UNKNOWN)},
			HttpResponse: &envoyAuthV3.CheckResponse_DeniedResponse{
				DeniedResponse: &envoyAuthV3.DeniedHttpResponse{
					Status: &envoyType.HttpStatus{Code: http.StatusInternalServerError},
					Headers: []*envoyCoreV3.HeaderValueOption{
						{Header: &envoyCoreV3.HeaderValue{Key: "Content-Type", Value: "application/json"}},
					},
					Body: `{"msg": "internal server error"}`,
				},
			},
		}, nil
	}
	log.Println("RequestURI: ", requestURI)

	// Read over and log the headers for the request
	denyHeader := false
	log.Println("|~~~~~~~~~~~~ BEGIN HEADERS ~~~~~~~~~~~~|")
	for k, v := range req.GetAttributes().GetRequest().GetHttp().GetHeaders() {
		log.Printf("%s: %s", k, v)
		// Sleep for x seconds when this header is present
		if k == "sleepfor" {
			seconds, _ := strconv.Atoi(v)
			log.Printf("%s%d%s", "Sleeping for ", seconds, " seconds...")
			time.Sleep(time.Duration(seconds) * time.Second)
		} else if k == "deny-me" {
			denyHeader = true
		}
	}
	log.Println("|~~~~~~~~~~~~ END HEADERS ~~~~~~~~~~~~|")

	if requestURI.Path == "/deny-me/" || denyHeader {
		log.Println("=> DENIED REQUEST", err)
		return &envoyAuthV3.CheckResponse{
			Status: &status.Status{Code: int32(code.Code_PERMISSION_DENIED)},
			HttpResponse: &envoyAuthV3.CheckResponse_DeniedResponse{
				DeniedResponse: &envoyAuthV3.DeniedHttpResponse{
					Status: &envoyType.HttpStatus{Code: http.StatusForbidden},
					Headers: []*envoyCoreV3.HeaderValueOption{
						{Header: &envoyCoreV3.HeaderValue{Key: "Content-Type", Value: "application/json"}},
					},
					Body: `{"msg": "Your request was denied, unauthorized path /deny-me/"}`,
				},
			},
		}, nil
	}

	//tokenString := "eyJhbGciOiJSUzI1NiIsImtpZCI6ImQwNWI0MDljNmYyMmM0MDNlMWY5MWY5ODY3YWM0OTJhOTA2MTk1NTgiLCJ0eXAiOiJKV1QifQ.eyJuYW1lIjoiaGFuZGVyIEZlcm5hbmRvICBHdXRpw6lycmV6IGPDs3Jkb2JhICIsInN0b3JlSWQiOjI1MDUxNywiaXNzIjoiaHR0cHM6Ly9zZWN1cmV0b2tlbi5nb29nbGUuY29tL2NoaXBlci1kZXZlbG9wbWVudCIsImF1ZCI6ImNoaXBlci1kZXZlbG9wbWVudCIsImF1dGhfdGltZSI6MTY3NTA5MDM0NywidXNlcl9pZCI6InlaUkFoM1FUdlVTR3hNNTlwQlNoeDIzakd4RjMiLCJzdWIiOiJ5WlJBaDNRVHZVU0d4TTU5cEJTaHgyM2pHeEYzIiwiaWF0IjoxNjc1MDkwMzgyLCJleHAiOjE2NzUwOTM5ODIsImVtYWlsIjoiaGFuZmVyMkBnbWFpbC5jb20iLCJlbWFpbF92ZXJpZmllZCI6dHJ1ZSwicGhvbmVfbnVtYmVyIjoiKzU3MzE4MjcyMzc1MSIsImZpcmViYXNlIjp7ImlkZW50aXRpZXMiOnsicGhvbmUiOlsiKzU3MzE4MjcyMzc1MSJdLCJlbWFpbCI6WyJoYW5mZXIyQGdtYWlsLmNvbSJdfSwic2lnbl9pbl9wcm92aWRlciI6ImN1c3RvbSJ9fQ.pIThe-7s3q8mxE0BpHBZ0zzWKHHDRmRo5xDgrbmZADHY4EMhemrsdo9kdDY42XeqEtqqdI6wVcpwdu8XwFH2Cz09APOfoSmxQUKqmVotcvT4m-xzbi-V-BHZT21KmrE_Kko1tEz7TKpF_l3s1ojM0Y_PzhtR6fc4hOZtmqA7j0oQuwDuN9LCEkSxTocf-7B9xQzpwE3JWPPbxTQO6Ttvm9fRRO6AKmUEnxr-45kcBIGF2pmoo8s4v_7PHjhetqdi8MBfsO9DjQQqoOQ0_zgjWH0lWvvYOKzCGyLJGPLt7H8_GPOHE3td1ndUxCF7VNJvMJSj7IGJyL9yDid26k2wMg"
	log.Print("-----------------prueba----------------------")
	res := req.GetAttributes().GetRequest().GetHttp().GetHeaders()
	tokenString := res["authorization"]
	log.Print(tokenString)
	conf := &firebase.Config{
		ServiceAccountID: os.Getenv("SERVICE_ACCOUNT_ID"),
		ProjectID:        os.Getenv("PROJECT_ID"),
	}
	app, err := firebase.NewApp(context.Background(), conf)
	if err != nil {
		log.Fatalf("error initializing app: %v\n", err)
	}

	log.Println(requestURI.Path)

	verifyIDToken(context.Background(), app, tokenString)
	log.Print("-----------------fin-prueba----------------------")
	log.Print("=> ALLOW REQUEST")
	return &envoyAuthV3.CheckResponse{
		Status: &status.Status{Code: int32(code.Code_OK)},
		HttpResponse: &envoyAuthV3.CheckResponse_OkResponse{
			OkResponse: &envoyAuthV3.OkHttpResponse{
				Headers: []*envoyCoreV3.HeaderValueOption{
					{
						Header: &envoyCoreV3.HeaderValue{Key: "V3AlphaOverwrite", Value: "HeaderOverwritten"},
						Append: &wrappers.BoolValue{Value: false},
					},
					{
						Header: &envoyCoreV3.HeaderValue{Key: "Authorization", Value: "HeaderAppended"},
						Append: &wrappers.BoolValue{Value: true},
					},
				},
			},
		},
	}, nil

}

func verifyIDToken(ctx context.Context, app *firebase.App, idToken string) *auth.Token {
	// [START verify_id_token_golang]
	client, err := app.Auth(ctx)
	if err != nil {
		log.Printf("error getting Auth client: %v\n", err)
	}

	token, err := client.VerifyIDToken(ctx, idToken)
	if err != nil {
		log.Printf("error verifying ID token: %v\n", err)
	}

	log.Printf("Verified ID token: %v\n", token)

	// [END verify_id_token_golang]

	return token
}
