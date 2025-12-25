using System;

namespace GoogleAnalytics.Ecommerce;

/// <summary>
/// Class to construct transaction/checkout or other product interaction related information for a Google Analytics hit. Use this class to report information about products sold, viewed or refunded. This class is intended to be used with <see cref="T:GoogleAnalytics.Ecommerce.Product" />. Instances of this class can be associated with <see cref="M:GoogleAnalytics.HitBuilder.SetProductAction(GoogleAnalytics.Ecommerce.ProductAction)" />.
/// </summary>
internal sealed class ProductAction
{
	/// <summary>
	/// Gets or sets the product action for all the products included in the hit.
	/// </summary>
	public string Action { get; private set; }

	/// <summary>
	/// Gets or sets the label associated with the checkout. This value is used for <see cref="F:GoogleAnalytics.Ecommerce.ActionEnum.Checkout" /> and <see cref="F:GoogleAnalytics.Ecommerce.ActionEnum.CheckoutOption" /> actions.
	/// </summary>
	public string CheckoutOptions { get; set; }

	/// <summary>
	/// Gets or sets the checkout processes's progress. This value is used for <see cref="F:GoogleAnalytics.Ecommerce.ActionEnum.Checkout" /> and <see cref="F:GoogleAnalytics.Ecommerce.ActionEnum.CheckoutOption" /> actions.
	/// </summary>
	public int? CheckoutStep { get; set; }

	/// <summary>
	/// Gets or sets the list name associated with the products in the analytics hit. This value is used for <see cref="F:GoogleAnalytics.Ecommerce.ActionEnum.Detail" /> and <see cref="F:GoogleAnalytics.Ecommerce.ActionEnum.Click" /> actions.
	/// </summary>
	public string ProductActionList { get; set; }

	/// <summary>
	/// Gets or sets the list source name associated with the products in the analytics hit. This value is used for <see cref="F:GoogleAnalytics.Ecommerce.ActionEnum.Detail" /> and <see cref="F:GoogleAnalytics.Ecommerce.ActionEnum.Click" /> actions.
	/// </summary>
	public string ProductListSource { get; set; }

	/// <summary>
	/// Gets or sets the transaction's affiliation value. This value is used for <see cref="F:GoogleAnalytics.Ecommerce.ActionEnum.Purchase" /> and <see cref="F:GoogleAnalytics.Ecommerce.ActionEnum.Refund" /> actions.
	/// </summary>
	public string TransactionAffiliation { get; set; }

	/// <summary>
	/// Gets or sets the coupon code used in a transaction. This value is used for <see cref="F:GoogleAnalytics.Ecommerce.ActionEnum.Purchase" /> and <see cref="F:GoogleAnalytics.Ecommerce.ActionEnum.Refund" /> actions.
	/// </summary>
	public string TransactionCouponCode { get; set; }

	/// <summary>
	/// The unique id associated with the transaction. This value is used for <see cref="F:GoogleAnalytics.Ecommerce.ActionEnum.Purchase" /> and <see cref="F:GoogleAnalytics.Ecommerce.ActionEnum.Refund" /> actions.
	/// </summary>
	public string TransactionId { get; set; }

	/// <summary>
	/// Gets or sets the transaction's total revenue. This value is used for <see cref="F:GoogleAnalytics.Ecommerce.ActionEnum.Purchase" /> and <see cref="F:GoogleAnalytics.Ecommerce.ActionEnum.Refund" /> actions.
	/// </summary>
	public double? TransactionRevenue { get; set; }

	/// <summary>
	/// Gets or sets the transaction's shipping costs. This value is used for <see cref="F:GoogleAnalytics.Ecommerce.ActionEnum.Purchase" /> and <see cref="F:GoogleAnalytics.Ecommerce.ActionEnum.Refund" /> actions.
	/// </summary>
	public double? TransactionShipping { get; set; }

	/// <summary>
	/// Gets or sets the transaction's total tax. This value is used for <see cref="F:GoogleAnalytics.Ecommerce.ActionEnum.Purchase" /> and <see cref="F:GoogleAnalytics.Ecommerce.ActionEnum.Refund" /> actions.
	/// </summary>
	public double? TransactionTax { get; set; }

	/// <summary>
	/// Creates a new instance of <see cref="T:GoogleAnalytics.Ecommerce.ProductAction" /> with the product action for all the products included in the hit. Valid values include "detail", "click", "add", "remove", "checkout", "checkout_option", "purchase" and "refund". All these values are also defined in this class for ease of use. You also also send additional values with the hit for some specific actions. See the action documentation for details.
	/// </summary>
	/// <param name="action">The action type to send.</param>
	public ProductAction(ActionEnum action)
	{
		Action = GetAction(action);
	}

	internal static string GetAction(ActionEnum action)
	{
		return action switch
		{
			ActionEnum.Add => "add", 
			ActionEnum.Checkout => "checkout", 
			ActionEnum.CheckoutOption => "checkout_option", 
			ActionEnum.Click => "click", 
			ActionEnum.Detail => "detail", 
			ActionEnum.Purchase => "purchase", 
			ActionEnum.Refund => "refund", 
			ActionEnum.Remove => "remove", 
			_ => throw new NotImplementedException(), 
		};
	}
}
