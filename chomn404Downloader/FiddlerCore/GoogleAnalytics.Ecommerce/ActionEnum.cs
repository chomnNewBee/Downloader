namespace GoogleAnalytics.Ecommerce;

/// <summary>
/// The product action for all the products included in the hit.
/// </summary>
public enum ActionEnum
{
	/// <summary>
	/// Action to use when a product is added to the cart.
	/// </summary>
	Add,
	/// <summary>
	/// Action to use for hits with checkout data.
	/// </summary>
	Checkout,
	/// <summary>
	/// Action to be used for supplemental checkout data that needs to be provided after a checkout hit.
	/// </summary>
	CheckoutOption,
	/// <summary>
	/// Action to use when the user clicks on a set of products.
	/// </summary>
	Click,
	/// <summary>
	/// Action to use when the user views detailed descriptions of products.
	/// </summary>
	Detail,
	/// <summary>
	/// Action that is used to report all the transaction data to GA.
	/// </summary>
	Purchase,
	/// <summary>
	/// Action to use while reporting refunded transactions to GA.
	/// </summary>
	Refund,
	/// <summary>
	/// Action to use when a product is removed from the cart.
	/// </summary>
	Remove
}
