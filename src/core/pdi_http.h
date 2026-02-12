/*
# Copyright 2022 University of California, Riverside
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# SPDX-License-Identifier: Apache-2.0
*/

#ifndef HTTP_H
#define HTTP_H

#include <rte_eal.h>
#include <stdint.h>

#define HTTP_MSG_LENGTH_HEADER_MAX (1U << 10)
#define HTTP_MSG_LENGTH_BODY_MAX (1U << 10)
#define HTTP_MSG_LENGTH_MAX (HTTP_MSG_LENGTH_HEADER_MAX + HTTP_MSG_LENGTH_BODY_MAX)

#define GATEWAY (uint8_t)0
#define FRONTEND (uint8_t)1
#define CURRENCY_SVC (uint8_t)2
#define PRODUCTCATA_SVC (uint8_t)3
#define CART_SVC (uint8_t)4
#define RECOMMEND_SVC (uint8_t)5
#define SHIPPING_SVC (uint8_t)6
#define CHECKOUT_SVC (uint8_t)7
#define PAYMENT_SVC (uint8_t)8
#define EMAIL_SVC (uint8_t)9
#define AD_SVC (uint8_t)10

#ifdef __cplusplus
extern "C"
{
#endif

typedef struct _money
{
    char CurrencyCode[10];
    int64_t Units;
    int32_t Nanos;
} Money;

typedef struct _address
{
    char StreetAddress[50];
    char City[15];
    char State[15];
    char Country[15];
    int32_t ZipCode;
} Address;

typedef struct _cartItem
{
    char ProductId[50];
    int32_t Quantity;
} CartItem;

typedef struct _orderItem
{
    CartItem Item;
    Money Cost;
} OrderItem;

typedef struct _orderResult
{
    char OrderId[40];
    char ShippingTrackingId[100];
    Money ShippingCost;
    Address ShippingAddress;
    OrderItem Items[10];
} OrderResult;

typedef struct _cart
{
    char UserId[50];
    int num_items;
    CartItem Items[10];
} Cart;

// typedef struct _addItemResponse{
// 	bool return_code; // 1 - success
// } AddItemResponse;

typedef struct _addItemRequest
{
    char UserId[50];
    CartItem Item;
} AddItemRequest;

typedef struct _emptyCartRequest
{
    char UserId[50];
} EmptyCartRequest;

typedef struct _getCartRequest
{
    char UserId[50];
} GetCartRequest;

typedef struct _product
{
    char Id[20];
    char Name[30];
    char Description[100];
    char Picture[60];
    Money PriceUsd;
    // Categories such as "clothing" or "kitchen" that can be used to look up
    // other related products.
    int num_categories;
    char Categories[10][20];
} Product;

typedef struct _productView
{
    Product Item;
    Money Price;
} productView;

typedef struct _cartItemView
{
    Product Item;
    int32_t Quantity;
    Money Price;
} cartItemView;

typedef struct _listProductsResponse
{
    int num_products;
    Product Products[9];
} ListProductsResponse;

typedef struct _searchProductsResponse
{
    int num_products;
    Product Results[9];
} SearchProductsResponse;

typedef struct _getProductRequest
{
    char Id[20];
} GetProductRequest;

typedef struct _searchProductsRequest
{
    char Query[50];
} SearchProductsRequest;

typedef struct _listRecommendationsRequest
{
    // char UserId[50];
    char ProductId[20];
} ListRecommendationsRequest;

typedef struct _listRecommendationsResponse
{
    char ProductId[20];
} ListRecommendationsResponse;

typedef struct _shipOrderRequest
{
    Address address;
    CartItem Items[10];
} ShipOrderRequest;

typedef struct _shipOrderResponse
{
    char TrackingId[100];
} ShipOrderResponse;

typedef struct _getQuoteRequest
{
    Address address;
    int num_items;
    CartItem Items[10];
} GetQuoteRequest;

typedef struct _sendOrderConfirmationRequest
{
    char Email[50];
    // OrderResult Order;
} SendOrderConfirmationRequest;

typedef struct _getQuoteResponse
{
    bool conversion_flag;
    Money CostUsd;
} GetQuoteResponse;

typedef struct _creditCardInfo
{
    char CreditCardNumber[30];
    int32_t CreditCardCvv;
    int32_t CreditCardExpirationYear;
    int32_t CreditCardExpirationMonth;
} CreditCardInfo;

typedef struct _orderPrep
{
    OrderItem orderItems[10];
    CartItem cartItems[10];
    Money shippingCostLocalized;
} orderPrep;

typedef struct _placeOrderRequest
{
    char UserId[50];
    char UserCurrency[5];
    Address address;
    char Email[50];
    CreditCardInfo CreditCard;
} PlaceOrderRequest;

typedef struct _chargeRequest
{
    Money Amount;
    CreditCardInfo CreditCard;
} ChargeRequest;

typedef struct _chargeResponse
{
    char TransactionId[40];
} ChargeResponse;

typedef struct _getSupportedCurrenciesResponse
{
    int num_currencies;
    char CurrencyCodes[6][10];
} GetSupportedCurrenciesResponse;

typedef struct _currencyConversionRequest
{
    Money From;
    char ToCode[10];
} CurrencyConversionRequest;

typedef struct _ad
{
    char RedirectUrl[100];
    char Text[100];
} Ad;

typedef struct _adrequest
{
    int num_context_keys;
    char ContextKeys[10][100];
} AdRequest;

typedef struct _adresponse
{
    int num_ads;
    Ad Ads[10];
} AdResponse;

struct pdin_rdma_md_s {
    /* pointer to received HTTP request */
    void *ngx_http_request_pt;
    /* pointer to callback handler */
    void *pdin_rdma_handler_pt;
    /* pointer to handler log */
    void *pdin_rdma_handler_log_pt;
    /* pointer to request mempool */
    void *ngx_http_request_mempool_pt;
}; // __attribute__((packed)) __rte_cache_aligned;

enum req_tp_t {
    AD = 0,
};

struct AdBody {
    AdRequest ad_request;
    AdResponse ad_response;
};

struct ChargeBody {
    ChargeRequest charge_request;
    ChargeResponse charge_response;
};

struct GetQuoteBody {
    GetQuoteRequest get_quote_request;
    GetQuoteResponse get_quote_response;

};

struct ShipOrderBody {
    ShipOrderRequest ship_order_request;
    ShipOrderResponse ship_order_response;

};

struct SearchProductsBody {
    SearchProductsRequest search_products_request;
    SearchProductsResponse search_products_response;

};

struct ListRecommendationsBody {
    ListRecommendationsRequest list_recommendations_request;
    ListRecommendationsResponse list_recommendations_response;

};

struct CartServiceBody {
    EmptyCartRequest empty_cart_request;
    AddItemRequest add_item_request;
    // bool add_item_response;
    GetCartRequest get_cart_request;
    Cart get_cart_response;

};


struct http_transaction
{
    uint32_t tenant_id;

    // used by spright mode to return to external client
    int sockfd;
    // can be removed using map in gtw
    void *sk_ctx;

    // TODO: provide by p-ing
    uint8_t ing_id;
    uint8_t term_id;

    // TODO: provide by p-ing
    uint8_t route_id;

    // TODO: to be decided
    uint8_t next_fn;
    uint8_t hop_count;
    uint8_t caller_fn;

    // TODO: p-ing structure
    struct pdin_rdma_md_s pdin_md;

    // uint8_t is_rdma_remote_mem;
    // uint32_t rdma_recv_qp_num;
    // uint32_t rdma_send_qp_num;
    // uint32_t rdma_recv_node_idx;
    // uint32_t rdma_send_node_idx;
    // uint32_t rdma_slot_idx;
    // uint32_t rdma_n_slot;
    // uint32_t rdma_remote_mr_idx;

    uint32_t length_request;
    uint32_t length_response;
    // should be in the enum req_tp_t
    int req_type;

    // nf_get
    // used for active nf send
    uint8_t nf_get;

    // TODO: deprecate soon use req_typ
    char rpc_handler[64];
    // enum evnet_type;
    char caller_nf[64];
    char request[HTTP_MSG_LENGTH_MAX];
    char response[HTTP_MSG_LENGTH_MAX];

    AdRequest ad_request;
    AdResponse ad_response;

    // TODO:
    CurrencyConversionRequest currency_conversion_req;
    Money currency_conversion_result;
    GetSupportedCurrenciesResponse get_supported_currencies_response;

    SendOrderConfirmationRequest email_req;

    ChargeRequest charge_request;
    ChargeResponse charge_response;

    GetQuoteRequest get_quote_request;
    GetQuoteResponse get_quote_response;
    ShipOrderRequest ship_order_request;
    ShipOrderResponse ship_order_response;

    SearchProductsRequest search_products_request;
    SearchProductsResponse search_products_response;

    // TODO:
    GetProductRequest get_product_request;
    Product get_product_response;
    ListProductsResponse list_products_response;

    EmptyCartRequest empty_cart_request;
    AddItemRequest add_item_request;
    // bool add_item_response;
    GetCartRequest get_cart_request;
    Cart get_cart_response;

    ListRecommendationsRequest list_recommendations_request;
    ListRecommendationsResponse list_recommendations_response;

    // TODO:
    productView product_view[9];
    int productViewCntr;

    // TODO:
    cartItemView cart_item_view[10];
    int cartItemViewCntr;
    int cartItemCurConvertCntr;
    Money total_price;

    PlaceOrderRequest place_order_request;
    orderPrep order_prep;
    OrderResult order_result;
    OrderItem order_item_view[10];
    int orderItemViewCntr;
    int orderItemCurConvertCntr;
    uint8_t checkoutsvc_hop_cnt;

    struct timespec timestamp;
};

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* HTTP_H */
