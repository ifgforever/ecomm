export async function onRequestGet(context) {
    try {
        const products = await context.env.PRODUCTS_KV.get("products", "json");
        return new Response(JSON.stringify(products || []), {
            headers: {
                "Content-Type": "application/json",
                "Access-Control-Allow-Origin": "*"
            }
        });
    } catch (error) {
        return new Response(JSON.stringify([]), {
            headers: { "Content-Type": "application/json" }
        });
    }
}

export async function onRequestPut(context) {
    try {
        const products = await context.request.json();
        await context.env.PRODUCTS_KV.put("products", JSON.stringify(products));
     return new Response(JSON.stringify({ success: true }), {
            headers: {
                "Content-Type": "application/json",
                "Access-Control-Allow-Origin": "*"
            }
        });
    } catch (error) {
        return new Response(JSON.stringify({ success: false, error: error.message }), {
            status: 500,
            headers: { "Content-Type": "application/json" }
        });
    }
}

export async function onRequestOptions() {
    return new Response(null, {
        headers: {
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Methods": "GET, PUT, OPTIONS",
            "Access-Control-Allow-Headers": "Content-Type"
        }
    });
}
