#include <string>
/*
https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Methods
https://www.rfc-editor.org/rfc/rfc7231
*/
namespace HTTP {
	namespace METHODS {
		using string = std::string;

		/*
			https://www.rfc-editor.org/rfc/rfc7231#section-4.2.1
			SAFE:
				[GET, HEAD, OPTIONS, TRACE]
				Request methods are considered "safe" if their defined semantics are
				essentially read-only; i.e., the client does not request, and does
				not expect, any state change on the origin server as a result of
				applying a safe method to a target resource.  Likewise, reasonable
				use of a safe method is not expected to cause any harm, loss of
				property, or unusual burden on the origin server.

			https://www.rfc-editor.org/rfc/rfc7231#section-4.2.2
			IDEMPOTENT:
				[GET, HEAD, OPTIONS, TRACE, PUT, DELETE]
				A request method is considered "idempotent" if the intended effect on
				the server of multiple identical requests with that method is the
				same as the effect for a single such request.  Of the request methods
				defined by this specification, PUT, DELETE, and safe request methods
				are idempotent.

			https://www.rfc-editor.org/rfc/rfc7231#section-4.2.3
			https://www.rfc-editor.org/rfc/rfc7234
			CACHEABLE:
				[GET, HEAD]
				Request methods can be defined as "cacheable" to indicate that
				responses to them are allowed to be stored for future reuse; for
				specific requirements see [RFC7234].  In general, safe methods that
				do not depend on a current or authoritative response are defined as
				cacheable; this specification defines GET, HEAD, and POST as
				cacheable, although the overwhelming majority of cache
				implementations only support GET and HEAD.
		*/

		/*
			https://www.rfc-editor.org/rfc/rfc7231#section-4.3.1

			Transfer a current representation of the target
			resource.

			A client can alter the semantics of GET to be a "range request",
			requesting transfer of only some part(s) of the selected
			representation, by sending a Range header field in the request ([RFC7233]).

			A payload within a GET request message has no defined semantics;
			sending a payload body on a GET request might cause some existing
			implementations to reject the request.

			The response to a GET request is cacheable; a cache MAY use it to
			satisfy subsequent GET and HEAD requests unless otherwise indicated
			by the Cache-Control header field (Section 5.2 of [RFC7234]).
		*/
		const string GET = "GET";

		/*
			https://www.rfc-editor.org/rfc/rfc7231#section-4.3.2

			Same as GET, but only transfer the status line
			and header section.

			The HEAD method is identical to GET except that the server MUST NOT
			send a message body in the response (i.e., the response terminates at
			the end of the header section).  The server SHOULD send the same
			header fields in response to a HEAD request as it would have sent if
			the request had been a GET, except that the payload header fields
			(Section 3.3) MAY be omitted.  This method can be used for obtaining
			metadata about the selected representation without transferring the
			representation data and is often used for testing hypertext links for
			validity, accessibility, and recent modification.

			The response to a HEAD request is cacheable; a cache MAY use it to
			satisfy subsequent HEAD requests unless otherwise indicated by the
			Cache-Control header field (Section 5.2 of [RFC7234]).  A HEAD
			response might also have an effect on previously cached responses to
			GET; see Section 4.3.5 of [RFC7234].
		*/
		const string HEAD = "HEAD";

		/*
			https://www.rfc-editor.org/rfc/rfc7231#section-4.3.3

			Perform resource-specific processing on the
			request payload.

			The POST method requests that the target resource process the
			representation enclosed in the request according to the resource's
			own specific semantics.  For example, POST is used for the following
			functions (among others):

			- Providing a block of data, such as the fields entered into an HTML
			form, to a data-handling process;

			- Posting a message to a bulletin board, newsgroup, mailing list,
			blog, or similar group of articles;

			- Creating a new resource that has yet to be identified by the
			origin server; and

			- Appending data to a resource's existing representation(s).

			An origin server indicates response semantics by choosing an
			appropriate status code depending on the result of processing the
			POST request; almost all of the status codes defined by this
			specification might be received in a response to POST (the exceptions
			being 206 (Partial Content), 304 (Not Modified), and 416 (Range Not
			Satisfiable)).

			If one or more resources has been created on the origin server as a
			result of successfully processing a POST request, the origin server
			SHOULD send a 201 (Created) response containing a Location header
			field that provides an identifier for the primary resource created
			(Section 7.1.2) and a representation that describes the status of the
			request while referring to the new resource(s).

			Responses to POST requests are only cacheable when they include
			explicit freshness information (see Section 4.2.1 of [RFC7234]).
			However, POST caching is not widely implemented.  For cases where an
			origin server wishes the client to be able to cache the result of a
			POST in a way that can be reused by a later GET, the origin server
			MAY send a 200 (OK) response containing the result and a
			Content-Location header field that has the same value as the POST's
			effective request URI (Section 3.1.4.2).
		*/
		const string POST = "POST";

		/*
			https://www.rfc-editor.org/rfc/rfc7231#section-4.3.4

			Replace all current representations of the
			target resource with the request payload.

			The PUT method requests that the state of the target resource be
			created or replaced with the state defined by the representation
			enclosed in the request message payload.  A successful PUT of a given
			representation would suggest that a subsequent GET on that same
			target resource will result in an equivalent representation being
			sent in a 200 (OK) response.  However, there is no guarantee that
			such a state change will be observable, since the target resource
			might be acted upon by other user agents in parallel, or might be
			subject to dynamic processing by the origin server, before any
			subsequent GET is received.  A successful response only implies that
			the user agent's intent was achieved at the time of its processing by
			the origin server.

			If the target resource does not have a current representation and the
			PUT successfully creates one, then the origin server MUST inform the
			user agent by sending a 201 (Created) response.  If the target
			resource does have a current representation and that representation
			is successfully modified in accordance with the state of the enclosed
			representation, then the origin server MUST send either a 200 (OK) or
			a 204 (No Content) response to indicate successful completion of the
			request.

			An origin server MUST NOT send a validator header field
			(Section 7.2), such as an ETag or Last-Modified field, in a
			successful response to PUT unless the request's representation data
			was saved without any transformation applied to the body (i.e., the
			resource's new representation data is identical to the representation
			data received in the PUT request) and the validator field value
			reflects the new representation.  This requirement allows a user
			agent to know when the representation body it has in memory remains
			current as a result of the PUT, thus not in need of being retrieved
			again from the origin server, and that the new validator(s) received
			in the response can be used for future conditional requests in order
			to prevent accidental overwrites (Section 5.2).

			The fundamental difference between the POST and PUT methods is
			highlighted by the different intent for the enclosed representation.
			The target resource in a POST request is intended to handle the
			enclosed representation according to the resource's own semantics,
			whereas the enclosed representation in a PUT request is defined as
			replacing the state of the target resource.  Hence, the intent of PUT
			is idempotent and visible to intermediaries, even though the exact
			effect is only known by the origin server.

			An origin server that allows PUT on a given target resource MUST send
			a 400 (Bad Request) response to a PUT request that contains a
			Content-Range header field (Section 4.2 of [RFC7233]), since the
			payload is likely to be partial content that has been mistakenly PUT
			as a full representation.  Partial content updates are possible by
			targeting a separately identified resource with state that overlaps a
			portion of the larger resource, or by using a different method that
			has been specifically defined for partial updates (for example, the
			PATCH method defined in [RFC5789]).

			Responses to the PUT method are not cacheable.  If a successful PUT
			request passes through a cache that has one or more stored responses
			for the effective request URI, those stored responses will be
			invalidated (see Section 4.4 of [RFC7234]).
		*/
		const string PUT = "PUT";

		/*
			https://www.rfc-editor.org/rfc/rfc7231#section-4.3.5

			Remove all current representations of the
			target resource.

			The DELETE method requests that the origin server remove the
			association between the target resource and its current
			functionality.  In effect, this method is similar to the rm command
			in UNIX: it expresses a deletion operation on the URI mapping of the
			origin server rather than an expectation that the previously
			associated information be deleted.

			If the target resource has one or more current representations, they
			might or might not be destroyed by the origin server, and the
			associated storage might or might not be reclaimed, depending
			entirely on the nature of the resource and its implementation by the
			origin server (which are beyond the scope of this specification).
			Likewise, other implementation aspects of a resource might need to be
			deactivated or archived as a result of a DELETE, such as database or
			gateway connections.  In general, it is assumed that the origin
			server will only allow DELETE on resources for which it has a
			prescribed mechanism for accomplishing the deletion.

			Relatively few resources allow the DELETE method -- its primary use
			is for remote authoring environments, where the user has some
			direction regarding its effect.  For example, a resource that was
			previously created using a PUT request, or identified via the
			Location header field after a 201 (Created) response to a POST
			request, might allow a corresponding DELETE request to undo those
			actions.  Similarly, custom user agent implementations that implement
			an authoring function, such as revision control clients using HTTP
			for remote operations, might use DELETE based on an assumption that
			the server's URI space has been crafted to correspond to a version
			repository.

			If a DELETE method is successfully applied, the origin server SHOULD
			send a 202 (Accepted) status code if the action will likely succeed
			but has not yet been enacted, a 204 (No Content) status code if the
			action has been enacted and no further information is to be supplied,
			or a 200 (OK) status code if the action has been enacted and the
			response message includes a representation describing the status.

			A payload within a DELETE request message has no defined semantics;
			sending a payload body on a DELETE request might cause some existing
			implementations to reject the request.

			Responses to the DELETE method are not cacheable.  If a DELETE
			request passes through a cache that has one or more stored responses
			for the effective request URI, those stored responses will be
			invalidated (see Section 4.4 of [RFC7234]).
		*/
		const string DELETE = "DELETE";

		/*
			https://www.rfc-editor.org/rfc/rfc7231#section-4.3.6

			Establish a tunnel to the server identified by
			the target resource.

			The CONNECT method requests that the recipient establish a tunnel to
			the destination origin server identified by the request-target and,
			if successful, thereafter restrict its behavior to blind forwarding
			of packets, in both directions, until the tunnel is closed.  Tunnels
			are commonly used to create an end-to-end virtual connection, through
			one or more proxies, which can then be secured using TLS (Transport
			Layer Security, [RFC5246]).

			CONNECT is intended only for use in requests to a proxy.  An origin
			server that receives a CONNECT request for itself MAY respond with a
			2xx (Successful) status code to indicate that a connection is
			established.  However, most origin servers do not implement CONNECT.

			...
		*/
		const string CONNECT = "CONNECT";

		/*
			https://www.rfc-editor.org/rfc/rfc7231#section-4.3.7

			Describe the communication options for the
			target resource.

			The OPTIONS method requests information about the communication
			options available for the target resource, at either the origin
			server or an intervening intermediary.  This method allows a client
			to determine the options and/or requirements associated with a
			resource, or the capabilities of a server, without implying a
			resource action.

			An OPTIONS request with an asterisk ("*") as the request-target
			(Section 5.3 of [RFC7230]) applies to the server in general rather
			than to a specific resource.  Since a server's communication options
			typically depend on the resource, the "*" request is only useful as a
			"ping" or "no-op" type of method; it does nothing beyond allowing the
			client to test the capabilities of the server.  For example, this can
			be used to test a proxy for HTTP/1.1 conformance (or lack thereof).

			If the request-target is not an asterisk, the OPTIONS request applies
			to the options that are available when communicating with the target
			resource.

			A server generating a successful response to OPTIONS SHOULD send any
			header fields that might indicate optional features implemented by
			the server and applicable to the target resource (e.g., Allow),
			including potential extensions not defined by this specification.
			The response payload, if any, might also describe the communication
			options in a machine or human-readable representation.  A standard
			format for such a representation is not defined by this
			specification, but might be defined by future extensions to HTTP.  A
			server MUST generate a Content-Length field with a value of "0" if no
			payload body is to be sent in the response.

			A client that generates an OPTIONS request containing a payload body
			MUST send a valid Content-Type header field describing the
			representation media type.  Although this specification does not
			define any use for such a payload, future extensions to HTTP might
			use the OPTIONS body to make more detailed queries about the target
			resource.

			Responses to the OPTIONS method are not cacheable.
		*/
		const string OPTIONS = "OPTIONS";

		/*
			https://www.rfc-editor.org/rfc/rfc7231#section-4.3.8

			Perform a message loop-back test along the path
			to the target resource.

			The TRACE method requests a remote, application-level loop-back of
			the request message.  The final recipient of the request SHOULD
			reflect the message received, excluding some fields described below,
			back to the client as the message body of a 200 (OK) response with a
			Content-Type of "message/http" (Section 8.3.1 of [RFC7230]).  The
			final recipient is either the origin server or the first server to
			receive a Max-Forwards value of zero (0) in the request
			(Section 5.1.2).

			A client MUST NOT generate header fields in a TRACE request
			containing sensitive data that might be disclosed by the response.
			For example, it would be foolish for a user agent to send stored user
			credentials [RFC7235] or cookies [RFC6265] in a TRACE request.  The
			final recipient of the request SHOULD exclude any request header
			fields that are likely to contain sensitive data when that recipient
			generates the response body.

			TRACE allows the client to see what is being received at the other
			end of the request chain and use that data for testing or diagnostic
			information.  The value of the Via header field (Section 5.7.1 of
			[RFC7230]) is of particular interest, since it acts as a trace of the
			request chain.  Use of the Max-Forwards header field allows the
			client to limit the length of the request chain, which is useful for
			testing a chain of proxies forwarding messages in an infinite loop.

			A client MUST NOT send a message body in a TRACE request.

			Responses to the TRACE method are not cacheable.
		*/
		const string TRACE = "TRACE";

	};
}


