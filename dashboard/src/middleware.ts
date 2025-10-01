import { clerkMiddleware, createRouteMatcher } from "@clerk/nextjs/server";

// DEMO MODE: Temporarily disable authentication for recording
// TODO: Re-enable after demo by uncommenting the protection below

// Define which routes require authentication
// Protect all routes by default (match everything)
const isProtectedRoute = createRouteMatcher([
  '/(.*)', // Protect all routes
]);

export default clerkMiddleware(async (auth, req) => {
  // DEMO MODE: Authentication temporarily disabled
  // Uncomment the lines below to re-enable authentication:
  
  // if (isProtectedRoute(req)) {
  //   await auth.protect();
  // }
});

export const config = {
  matcher: [
    // Skip Next.js internals and all static files, unless found in search params
    "/((?!_next|[^?]*\.(?:html?|css|js(?!on)|jpe?g|webp|png|gif|svg|ttf|woff2?|ico|csv|docx?|xlsx?|zip|webmanifest)).*)",
    // Always run for API routes
    "/(api|trpc)(.*)",
  ],
};
